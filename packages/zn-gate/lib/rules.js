'use strict';

const fs = require('fs');
const path = require('path');

/**
 * zn deterministic rules engine - SINGLE SOURCE OF TRUTH.
 * RULES_VERSION: 2026-09-06.3
 */

const RULES_VERSION = '2026-09-06.3';

const INJECTION_RULES = [
  { id: 'pi:ignore_previous', pattern: /ignore\s+(all\s+)?(previous|prior|above)/i, description: 'Override prior instructions' },
  { id: 'pi:disregard', pattern: /disregard\s+(all\s+)?(previous|prior|instructions)/i, description: 'Disregard instructions' },
  { id: 'pi:forget', pattern: /forget\s+(everything|all|your)/i, description: 'Forget-context attack' },
  { id: 'pi:identity_override', pattern: /you\s+are\s+now/i, description: 'Identity override' },
  { id: 'pi:new_instructions', pattern: /new\s+instructions?:/i, description: 'Instruction replacement' },
  { id: 'pi:system_tag', pattern: /(?:^|[\r\n"'`\[<])\s*system\s*:\s*|<[\s/]*system\b[^>]*>/i, description: 'Fake system tag' },
  { id: 'pi:system_bracket', pattern: /\[system\]/i, description: 'Bracketed system tag' },
  { id: 'pi:act_as', pattern: /act\s+as\s+(if|a)/i, description: 'Role hijack (act as)' },
  { id: 'pi:pretend', pattern: /pretend\s+(you|to\s+be)/i, description: 'Role hijack (pretend)' },
  { id: 'pi:roleplay', pattern: /roleplay\s+as/i, description: 'Role hijack (roleplay)' },
  { id: 'pi:jailbreak', pattern: /\bjailbreak\b/i, description: 'Explicit jailbreak term' },
  { id: 'pi:bypass', pattern: /bypass\s+(your|the|all)/i, description: 'Guardrail bypass attempt' },
  { id: 'pi:override', pattern: /override\s+(your|the|all)/i, description: 'Policy override attempt' },
  { id: 'pi:template_boundary', pattern: /\[INST\]|\[\/INST\]|<<<SYS>>>|<\/<<SYS>>>|<\|im_start\|>|<\|im_end\|>/i, description: 'Chat template boundary injection' },
];

const INDIRECT_INJECTION_RULES = [
  {
    id: 'indirect:html_comment',
    pattern: /<!--\s*(?:system|instruction|prompt|override|command)\s*:/i,
    description: 'Hidden instruction in HTML comment',
  },
  {
    id: 'indirect:hidden_tag',
    pattern: /<[a-z0-9]+\b[^>]*\b(?:display\s*:\s*none|visibility\s*:\s*hidden|hidden\b)[^>]*>[\s\S]*?(?:ignore|system|instruction|prompt|bypass|override)/i,
    description: 'Hidden DOM element with injection payload',
  },
];

const EXFIL_VERB_SOURCE = '\\b(give|reveal|send|show|print|expose|leak|paste|dump)\\b';
const CRED_OBJECT_SOURCE =
  '\\b(passwords?|api[_ -]?keys?|secrets?|credentials?|tokens?|ssh[ _-]?keys?|private[ _-]?keys?)\\b|(?:^|\\W)\\.env\\b';

const EXFIL_RULES = [
  {
    id: 'exfil:credentials',
    compound: [new RegExp(EXFIL_VERB_SOURCE, 'i'), new RegExp(CRED_OBJECT_SOURCE, 'i')],
    description: 'Imperative verb requesting credentials/secrets',
  },
];

const SENSITIVE_PATH_RULES = [
  {
    id: 'path:sensitive_file',
    pattern: /(?:~|\/home\/[^\s/]+|\/root)?\/\.(?:ssh\/(?:id_rsa|id_ed25519|authorized_keys)|aws\/credentials|env(?:\.local)?)\b|\/etc\/(?:shadow|passwd)\b/i,
    description: 'Targeting sensitive system credentials or environment file',
  },
];

const MARKDOWN_EXFIL_RULES = [
  {
    id: 'exfil:markdown_image',
    pattern: /!\[[^\]]*\]\(https?:\/\/[^\s\)]+[\?&](?:key|token|pass|secret|cred|data|val|leak|exfil)=[^)]*\)/i,
    description: 'Covert exfiltration via markdown image URL parameter',
  },
];

// Local custom rules cache (.znrules or zn.config.json)
let customConfig = null;
let lastConfigCheck = 0;

function loadCustomConfig(forceReload = false) {
  const now = Date.now();
  if (!forceReload && customConfig !== null && now - lastConfigCheck < 5000) {
    return customConfig;
  }
  lastConfigCheck = now;
  customConfig = { bannedPatterns: [], forbiddenPaths: [] };

  const candidates = [
    path.join(process.cwd(), '.znrules'),
    path.join(process.cwd(), 'zn.config.json'),
  ];

  for (const file of candidates) {
    if (fs.existsSync(file)) {
      try {
        if (file.endsWith('.json')) {
          const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
          if (Array.isArray(parsed.bannedPatterns)) {
            customConfig.bannedPatterns = parsed.bannedPatterns.map((p) => new RegExp(p, 'i'));
          }
          if (Array.isArray(parsed.forbiddenPaths)) {
            customConfig.forbiddenPaths = parsed.forbiddenPaths;
          }
        } else {
          const lines = fs.readFileSync(file, 'utf8').split('\n');
          for (let line of lines) {
            line = line.trim();
            if (!line || line.startsWith('#')) continue;
            if (line.startsWith('path:')) {
              customConfig.forbiddenPaths.push(line.slice(5).trim());
            } else {
              customConfig.bannedPatterns.push(new RegExp(line, 'i'));
            }
          }
        }
      } catch (err) {
        // Silently ignore malformed custom configs in production
      }
      break;
    }
  }
  return customConfig;
}

const HOMOGLYPH_MAP = {
  '\u0430': 'a', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p', '\u0441': 'c',
  '\u0456': 'i', '\u0455': 's', '\u0443': 'y', '\u0445': 'x',
  '\u0410': 'A', '\u0415': 'E', '\u041e': 'O', '\u0420': 'P', '\u0421': 'C',
};
const ZERO_WIDTH_RE = /[\u200B-\u200D\uFEFF\u00AD]/g;
const B64_EXEC_RE = /(?:echo|printf)\s+([A-Za-z0-9+/=]{16,})\s*\|\s*(?:base64\s+-(?:d|-decode)|openssl)/i;

function normalizeInput(str) {
  if (typeof str !== 'string') return '';
  // 1. Strip zero-width evasion characters
  let clean = str.replace(ZERO_WIDTH_RE, '');
  // 2. Strip inline C-style comments (e.g. sys/*safe*/tem -> system)
  clean = clean.replace(/\/\*[\s\S]*?\*\//g, '');
  // 3. Normalize homoglyphs
  clean = clean.replace(/[\u0410-\u0456]/g, (m) => HOMOGLYPH_MAP[m] || m);
  // 4. Rejoin words split across newlines (e.g. sys\ntem -> system)
  clean = clean.replace(/([a-zA-Z]{2,})\s*\n\s*([a-zA-Z]{2,})/g, '$1$2');
  return clean;
}

function evaluate(input, options = {}) {
  if (typeof input !== 'string') {
    return { verdict: 'allow', confidence: 1.0, rule: 'none', reason: null, engine: 'oss-local', rules_version: RULES_VERSION };
  }

  // Pre-normalization pass to defuse homoglyphs and zero-width evasion
  const normalized = normalizeInput(input);

  // Check Base64 payload smuggling
  const b64Match = normalized.match(B64_EXEC_RE);
  if (b64Match && b64Match[1]) {
    try {
      const decoded = Buffer.from(b64Match[1], 'base64').toString('utf8');
      const innerRes = evaluate(decoded, options);
      if (innerRes.verdict === 'block') {
        return {
          ...innerRes,
          reason: `Smuggled Base64 execution: ${innerRes.reason || innerRes.rule}`,
          rule: 'evasion:base64_smuggling',
        };
      }
    } catch (e) {
      // ignore invalid base64
    }
  }

  // Check against both original and normalized string
  const targets = normalized !== input ? [normalized, input] : [input];

  for (const text of targets) {
    // 1. Covert Markdown Image Exfiltration
    for (const rule of MARKDOWN_EXFIL_RULES) {
      if (rule.pattern.test(text)) {
        return { verdict: 'block', confidence: 0.98, reason: rule.description, rule: rule.id, engine: 'oss-local', rules_version: RULES_VERSION };
      }
    }

    // 2. Sensitive Path Traversal / Credential File Access
    for (const rule of SENSITIVE_PATH_RULES) {
      if (rule.pattern.test(text)) {
        return { verdict: 'block', confidence: 0.92, reason: rule.description, rule: rule.id, engine: 'oss-local', rules_version: RULES_VERSION };
      }
    }

    // 3. Indirect Injection Rules (HTML comments / hidden elements)
    for (const rule of INDIRECT_INJECTION_RULES) {
      if (rule.pattern.test(text)) {
        return { verdict: 'block', confidence: 0.95, reason: rule.description, rule: rule.id, engine: 'oss-local', rules_version: RULES_VERSION };
      }
    }

    // 4. Standard Prompt Injection Rules
    for (const rule of INJECTION_RULES) {
      if (rule.pattern.test(text)) {
        return { verdict: 'block', confidence: 0.95, reason: rule.description, rule: rule.id, engine: 'oss-local', rules_version: RULES_VERSION };
      }
    }

    // 5. Exfiltration Rules
    for (const rule of EXFIL_RULES) {
      if (rule.compound.every((re) => re.test(text))) {
        return { verdict: 'block', confidence: 0.9, reason: rule.description, rule: rule.id, engine: 'oss-local', rules_version: RULES_VERSION };
      }
    }
  }

  // 6. Project-specific Custom Rules (.znrules / zn.config.json)
  const cfg = loadCustomConfig();
  for (const pat of cfg.bannedPatterns) {
    if (pat.test(input)) {
      return { verdict: 'block', confidence: 1.0, reason: `Matches custom repository rule: ${pat.source}`, rule: 'custom:banned_pattern', engine: 'oss-local', rules_version: RULES_VERSION };
    }
  }
  for (const fpath of cfg.forbiddenPaths) {
    if (input.includes(fpath)) {
      return { verdict: 'block', confidence: 1.0, reason: `Matches custom repository forbidden path: ${fpath}`, rule: 'custom:forbidden_path', engine: 'oss-local', rules_version: RULES_VERSION };
    }
  }

  return { verdict: 'allow', confidence: 0.99, rule: 'none', reason: null, engine: 'oss-local', rules_version: RULES_VERSION };
}

module.exports = {
  evaluate,
  analyzePrompt: evaluate,
  loadCustomConfig,
  RULES_VERSION,
  INJECTION_RULES,
  INDIRECT_INJECTION_RULES,
  EXFIL_RULES,
  SENSITIVE_PATH_RULES,
  MARKDOWN_EXFIL_RULES,
};
