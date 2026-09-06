'use strict';

const https = require('https');
const http = require('http');
const { URL } = require('url');
const { evaluate, RULES_VERSION } = require('./rules');

function resolveEndpoint(options = {}) {
  if (options.apiUrl || process.env.ZN_API_URL) {
    return options.apiUrl || process.env.ZN_API_URL;
  }
  const stage = options.stage || process.env.ZN_STAGE || 'v30';
  if (stage === 'prod') {
    return 'https://api.usezn.com/prod/analyze';
  }
  return 'https://api.usezn.com/v30/analyze';
}

function analyzeCloud(input, apiKey, endpointUrl, timeoutMs = 4000) {
  return new Promise((resolve, reject) => {
    const url = new URL(endpointUrl);
    const postData = JSON.stringify({ input });
    const isHttps = url.protocol === 'https:';
    const lib = isHttps ? https : http;

    const req = lib.request(
      url,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(postData),
          Authorization: `Bearer ${apiKey.trim()}`,
          'User-Agent': 'zn-gate/1.2.4 (mcp-client)',
        },
        timeout: timeoutMs,
      },
      (res) => {
        let body = '';
        res.on('data', (chunk) => (body += chunk));
        res.on('end', () => {
          if (res.statusCode >= 200 && res.statusCode < 300) {
            try {
              const parsed = JSON.parse(body);
              const stageName = endpointUrl.includes('/v30') ? 'cloud-v30' : 'cloud-prod';
              resolve({ ...parsed, engine: stageName });
            } catch (err) {
              reject(new Error(`Failed to parse gateway response: ${err.message}`));
            }
          } else {
            reject(new Error(`Gateway responded with HTTP ${res.statusCode}: ${body.slice(0, 120)}`));
          }
        });
      }
    );

    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Gateway request timed out'));
    });

    req.on('error', (err) => reject(err));
    req.write(postData);
    req.end();
  });
}

async function analyze(input, options = {}) {
  const apiKey = options.apiKey || process.env.ZN_API_KEY;
  const forceLocal = options.localOnly || process.env.ZN_LOCAL_ONLY === 'true';

  // 1. Hybrid Fast-Path: Deterministic in-process evaluation (< 10µs, $0 cost)
  const local = evaluate(input, options);
  if (local.verdict === 'block') {
    return {
      ...local,
      mode: 'hybrid-local-fastpath',
      latency_us: 5,
    };
  }

  if (!apiKey || forceLocal) {
    return {
      ...local,
      mode: 'oss-local',
      tip: 'Set ZN_API_KEY to enable neural multilingual protection via usezn cloud gate',
    };
  }

  // 2. Cloud Gate deep neural analysis
  const endpoint = resolveEndpoint(options);
  try {
    const cloudRes = await analyzeCloud(input, apiKey, endpoint, options.timeout || 4000);
    return {
      ...cloudRes,
      mode: 'hybrid-cloud',
    };
  } catch (err) {
    if (process.env.DEBUG || process.env.ZN_VERBOSE) {
      process.stderr.write(`[zn-gate] Warning: Cloud gate error (${err.message}). Using local OSS rules fallback.\n`);
    }
    return {
      ...local,
      fallback: true,
      cloud_error: err.message,
    };
  }
}

/**
 * Inspect third-party tool output before LLM context assimilation.
 * Defends against Indirect Prompt Injection.
 */
async function checkToolResult(toolName, content, options = {}) {
  const textContent = typeof content === 'string' ? content : JSON.stringify(content);
  
  // Fast-path for empty or tiny benign returns
  if (!textContent || textContent.length < 5) {
    return {
      tool_name: toolName,
      safe_to_ingest: true,
      sanitized_content: textContent,
      assessment: { verdict: 'allow', confidence: 1.0, rule: 'none' },
    };
  }

  // Scan the tool output
  const assessment = await analyze(textContent, options);
  const isBlock = assessment.verdict?.toLowerCase() === 'block';

  return {
    tool_name: toolName,
    safe_to_ingest: !isBlock,
    assessment,
    sanitized_content: isBlock
      ? `[REDACTED BY ZN-GATE: Malicious prompt injection or exfiltration payload detected in ${toolName} output (${assessment.reason || assessment.rule})]`
      : textContent,
  };
}

module.exports = {
  analyze,
  checkToolResult,
  resolveEndpoint,
  evaluate,
  RULES_VERSION,
};
