'use strict';

const fs = require('fs');
const path = require('path');

/**
 * zn deterministic rules engine - SINGLE SOURCE OF TRUTH.
 * RULES_VERSION: 2026-09-06.3
 */

const RULES_VERSION = '2026-09-06.3';

const INJECTION_RULES = [
  { id: 'pi:ignore_previous', pattern: /ignore\s+(all\s+)?(the\s+)?(previous|prior|above)/i, description: 'Override prior instructions' },
  { id: 'pi:disregard', pattern: /disregard\s+(all\s+)?(previous|prior|instructions)/i, description: 'Disregard instructions' },
  { id: 'pi:forget', pattern: /forget\s+(about\s+)?(everything|all|your)/i, description: 'Forget-context attack' },
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
  { id: 'pi:multi_es', pattern: /ignora\s+(todas\s+las\s+)?(instrucciones|anteriores|previas)|olvida\s+(todo|las\s+instrucciones)|act[uú]a\s+como|ahora\s+eres/iu, description: 'Multilingual prompt injection (Spanish)' },
  { id: 'pi:multi_fr', pattern: /ignore[rz]?\s+(toutes\s+les\s+)?instructions|oublie[rz]?\s+tout|agis\s+comme|tu\s+es\s+maintenant/iu, description: 'Multilingual prompt injection (French)' },
  { id: 'pi:multi_ru', pattern: /забудь\s+.*?(все|инструкции)|игнорируй\s+.*?(все|предыдущие)|действуй\s+как|ты\s+теперь|найди\s+пароли/iu, description: 'Multilingual prompt injection (Russian)' },
  { id: 'pi:multi_zh', pattern: /忽略.*?(指示|指令|提示)|忘记.*?(指示|指令|一切)|你现在是|初始提示词/u, description: 'Multilingual prompt injection (Chinese)' },
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

const EXFIL_VERB_SOURCE = '\\b(give|reveal|send|show|print|expose|leak|paste|dump|read|open|cat|fetch|extract|steal)\\b';
const CRED_OBJECT_SOURCE =
  '\\b(passwords?|api[_ -]?keys?|secrets?|credentials?|tokens?|ssh[ _-]?keys?|private[ _-]?keys?|aws_secret[a-z0-9_]*|aws_access[a-z0-9_]*)\\b|(?:^|\\s|[\'"\`])\\.env(?:\\.[a-z0-9]+)?\\b';

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
    pattern: /(?:^|[\s"'`(\[])(?:~|\/home\/[^\s/]+|\/root)?\/?\.(?:ssh\/(?:id_rsa|id_ed25519|authorized_keys)|aws\/credentials|env(?:\.[a-z0-9]+)?)\b|\/etc\/(?:shadow|passwd)\b/i,
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
  if (typeof str !== 'string') return { normalized: '', stripped: '' };
  // 1. Strip zero-width evasion characters
  let stripped = str.replace(ZERO_WIDTH_RE, '');
  // 2. Strip inline C-style comments (e.g. sys/*safe*/tem -> system)
  stripped = stripped.replace(/\/\*[\s\S]*?\*\//g, '');
  // 3. Rejoin words and tokens split across newlines (e.g. sys\ntem -> system, /l\neak -> /leak, Cyrillic & Chinese)
  stripped = stripped.replace(/([\p{L}\p{N}_<|/.-]{1,})\s*[\r\n]+\s*([\p{L}\p{N}_>|/.-]{1,})/gu, '$1$2');
  // 4. Normalize homoglyphs (Cyrillic to Latin for English hijack detection)
  let normalized = stripped.replace(/[\u0410-\u0456]/g, (m) => HOMOGLYPH_MAP[m] || m);
  return { normalized, stripped };
}

function evaluate(input, options = {}) {
  if (typeof input !== 'string') {
    return { verdict: 'allow', confidence: 1.0, rule: 'none', reason: null, engine: 'oss-local', rules_version: RULES_VERSION };
  }

  // Pre-normalization passes: stripped (preserves non-Latin) and normalized (maps homoglyphs)
  const { normalized, stripped } = normalizeInput(input);

  // Check Base64 payload smuggling
  const b64Match = normalized.match(B64_EXEC_RE) || stripped.match(B64_EXEC_RE);
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

  // Check against normalized, stripped, and raw input
  const targets = Array.from(new Set([normalized, stripped, input]));

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

// -------------------------------------------------------------------------
// DLP & Secret Masking Rules
// -------------------------------------------------------------------------
const SECRET_PATTERNS = [
  { id: 'secret:private_key', pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, replacement: '[REDACTED_PRIVATE_KEY]' },
  { id: 'secret:anthropic_key', pattern: /\b(sk-ant-[A-Za-z0-9_-]{30,})\b/g, replacement: '[REDACTED_ANTHROPIC_KEY]' },
  { id: 'secret:openai_key', pattern: /\b(sk-(?!ant-)(?:proj-|svcacct-|none-)?[A-Za-z0-9_-]{28,})\b/g, replacement: '[REDACTED_OPENAI_KEY]' },
  { id: 'secret:aws_access_key', pattern: /\b(AKIA[0-9A-Z]{16})\b/g, replacement: '[REDACTED_AWS_KEY]' },
  { id: 'secret:aws_secret_key', pattern: /(aws_secret_access_key|aws_secret|aws_key)\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/gi, replacement: "$1='[REDACTED_AWS_SECRET]'" },
  { id: 'secret:github_token', pattern: /\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,40}|github_pat_[A-Za-z0-9_]{82})\b/g, replacement: '[REDACTED_GITHUB_TOKEN]' },
  { id: 'secret:db_url_password', pattern: /((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^:\s\/]+:)([^@\s\/]+)(@)/gi, replacement: '$1[REDACTED_DB_PASSWORD]$3' },
  { id: 'secret:jwt_token', pattern: /\b(eyJ[A-Za-z0-9-_=]{10,}\.eyJ[A-Za-z0-9-_=]{10,}\.[A-Za-z0-9-_.+/=]{10,})\b/g, replacement: '[REDACTED_JWT]' },
  { id: 'secret:env_credential', pattern: /\b((?:AWS_SECRET_ACCESS_KEY|SECRET_KEY|API_KEY|AUTH_TOKEN|PRIVATE_KEY|DATABASE_PASSWORD)\s*[:=]\s*['"]?)([^\s'"]{12,})(['"]?)/gi, replacement: '$1[REDACTED_SECRET]$3' },
];

function redactSecrets(text) {
  if (typeof text !== 'string' || !text) {
    return { sanitized: text, detections: [] };
  }
  let sanitized = text;
  const detections = [];
  for (const item of SECRET_PATTERNS) {
    let match;
    const regex = new RegExp(item.pattern.source, item.pattern.flags);
    while ((match = regex.exec(sanitized)) !== null) {
      detections.push({
        rule: item.id,
        index: match.index,
      });
    }
    sanitized = sanitized.replace(item.pattern, item.replacement);
  }
  return { sanitized, detections };
}

function sanitizeToolResult(toolOrResult, content, options = {}) {
  if (content !== undefined && content !== null) {
    const toolName = String(toolOrResult);
    const textContent = typeof content === 'string' ? content : JSON.stringify(content);
    const assessment = evaluate(textContent, options);
    const isBlock = assessment.verdict?.toLowerCase() === 'block';

    let sanitized = textContent;
    let secretsRedacted = 0;

    if (isBlock) {
      sanitized = `[REDACTED BY ZN-GATE: Malicious prompt injection payload detected in ${toolName} output (${assessment.reason || assessment.rule})]`;
    } else if (options.maskSecrets !== false) {
      const res = redactSecrets(textContent);
      sanitized = res.sanitized;
      secretsRedacted = res.detections.length;
    }

    return {
      tool_name: toolName,
      safe_to_ingest: !isBlock,
      assessment,
      secrets_redacted: secretsRedacted,
      sanitized_content: sanitized,
    };
  }

  // Deep sanitization of objects/arrays
  const detections = [];
  function _sanitize(val) {
    if (typeof val === 'string') {
      const res = redactSecrets(val);
      if (res.detections.length > 0) {
        detections.push(...res.detections);
      }
      return res.sanitized;
    } else if (Array.isArray(val)) {
      return val.map(_sanitize);
    } else if (val !== null && typeof val === 'object') {
      const out = {};
      for (const [k, v] of Object.entries(val)) {
        out[k] = _sanitize(v);
      }
      return out;
    }
    return val;
  }

  const sanitized = _sanitize(toolOrResult);
  return { sanitized, detections };
}

module.exports = {
  evaluate,
  analyzePrompt: evaluate,
  loadCustomConfig,
  redactSecrets,
  sanitizeToolResult,
  SECRET_PATTERNS,
  RULES_VERSION,
  INJECTION_RULES,
  INDIRECT_INJECTION_RULES,
  EXFIL_RULES,
  SENSITIVE_PATH_RULES,
  MARKDOWN_EXFIL_RULES,
};
