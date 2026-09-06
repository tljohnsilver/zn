'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const http = require('http');

const ZN_DIR = path.join(os.homedir(), '.zn');
const EVIDENCE_FILE = path.join(ZN_DIR, 'evidence.jsonl');
const GENESIS_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

function ensureZnDir(filePath = EVIDENCE_FILE) {
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

/**
 * Reads the last record's hash from the ledger.
 */
function getLastHash(filePath = EVIDENCE_FILE) {
  if (!fs.existsSync(filePath)) {
    return GENESIS_HASH;
  }
  try {
    const data = fs.readFileSync(filePath, 'utf8').trim();
    if (!data) return GENESIS_HASH;
    const lines = data.split('\n');
    const lastLine = lines[lines.length - 1];
    const parsed = JSON.parse(lastLine);
    return parsed.record_hash || GENESIS_HASH;
  } catch {
    return GENESIS_HASH;
  }
}

/**
 * Records a security event with cryptographic hash-chaining.
 *
 * @param {object} event - Event details (agent, phase, tool_name, payload, verdict, rule, reason, latency_us, engine)
 * @param {string} [filePath] - Optional ledger path
 * @returns {object} The recorded evidence record
 */
function logEvidence(event, filePath = EVIDENCE_FILE) {
  ensureZnDir(filePath);

  const prevHash = getLastHash(filePath);
  const timestamp = new Date().toISOString();
  const id = 'ev_' + Date.now().toString(36) + '_' + crypto.randomBytes(4).toString('hex');
  
  const payloadStr = typeof event.payload === 'string' ? event.payload : JSON.stringify(event.payload || '');
  const payloadSha256 = crypto.createHash('sha256').update(payloadStr).digest('hex');

  const baseRecord = {
    id,
    timestamp,
    agent_environment: event.agent || event.agent_environment || 'unknown',
    phase: event.phase || 'tool-call',
    tool_name: event.tool_name || event.tool || 'unknown',
    payload_sha256: payloadSha256,
    payload_preview: payloadStr.slice(0, 120),
    verdict: event.verdict || 'allow',
    rule: event.rule || null,
    reason: event.reason || null,
    confidence: event.confidence || 1.0,
    latency_us: event.latency_us || 0,
    engine: event.engine || 'oss-deterministic',
    prev_hash: prevHash,
  };

  // Compute record hash over prev_hash + canonical serialized content
  const recordHash = crypto
    .createHash('sha256')
    .update(prevHash + ':' + JSON.stringify(baseRecord))
    .digest('hex');

  const finalRecord = { ...baseRecord, record_hash: recordHash };

  fs.appendFileSync(filePath, JSON.stringify(finalRecord) + '\n', 'utf8');
  return finalRecord;
}

/**
 * Verifies the cryptographic integrity of the entire evidence chain.
 *
 * @param {string} [filePath] - Optional ledger path
 * @returns {object} { valid: boolean, total: number, verified: number, broken_index: number|null, error: string|null }
 */
function verifyEvidenceLedger(filePath = EVIDENCE_FILE) {
  if (!fs.existsSync(filePath)) {
    return { valid: true, total: 0, verified: 0, broken_index: null, error: null };
  }

  const lines = fs.readFileSync(filePath, 'utf8').trim().split('\n').filter(Boolean);
  let expectedPrevHash = GENESIS_HASH;

  for (let i = 0; i < lines.length; i++) {
    let rec;
    try {
      rec = JSON.parse(lines[i]);
    } catch (e) {
      return { valid: false, total: lines.length, verified: i, broken_index: i, error: `Malformed JSON at line ${i + 1}: ${e.message}` };
    }

    if (rec.prev_hash !== expectedPrevHash) {
      return {
        valid: false,
        total: lines.length,
        verified: i,
        broken_index: i,
        error: `Broken chain link at line ${i + 1} (record ${rec.id}): expected prev_hash ${expectedPrevHash.slice(0, 8)}... but found ${rec.prev_hash?.slice(0, 8)}...`
      };
    }

    const { record_hash, ...baseRecord } = rec;
    const computedHash = crypto
      .createHash('sha256')
      .update(expectedPrevHash + ':' + JSON.stringify(baseRecord))
      .digest('hex');

    if (computedHash !== record_hash) {
      return {
        valid: false,
        total: lines.length,
        verified: i,
        broken_index: i,
        error: `Tamper detected at line ${i + 1} (record ${rec.id}): hash mismatch. The content of this log was altered!`
      };
    }

    expectedPrevHash = record_hash;
  }

  return { valid: true, total: lines.length, verified: lines.length, broken_index: null, error: null };
}

/**
 * Generates aggregated metrics from the ledger.
 */
function getEvidenceStats(filePathOrLimit = EVIDENCE_FILE, maybeLimit = 50) {
  let filePath = EVIDENCE_FILE;
  let limit = 50;

  if (typeof filePathOrLimit === 'number') {
    limit = filePathOrLimit;
  } else if (typeof filePathOrLimit === 'string') {
    filePath = filePathOrLimit;
    if (typeof maybeLimit === 'number') limit = maybeLimit;
  }

  if (!fs.existsSync(filePath)) {
    return { total: 0, blocks: 0, blocked: 0, allows: 0, allowed: 0, shadows: 0, valid: true, top_rules: {}, top_tools: {}, recent: [] };
  }

  const lines = fs.readFileSync(filePath, 'utf8').trim().split('\n').filter(Boolean);
  let blocked = 0;
  let allowed = 0;
  let shadows = 0;
  const topRules = {};
  const topTools = {};
  const recent = [];

  for (let i = lines.length - 1; i >= 0; i--) {
    try {
      const rec = JSON.parse(lines[i]);
      if (rec.verdict === 'block') {
        blocked++;
        if (rec.rule) topRules[rec.rule] = (topRules[rec.rule] || 0) + 1;
      } else if (rec.verdict === 'shadow') {
        shadows++;
        if (rec.rule) topRules[rec.rule] = (topRules[rec.rule] || 0) + 1;
      } else {
        allowed++;
      }
      if (rec.tool_name) topTools[rec.tool_name] = (topTools[rec.tool_name] || 0) + 1;
      if (recent.length < limit) {
        recent.push(rec);
      }
    } catch {}
  }

  const check = verifyEvidenceLedger(filePath);

  return {
    total: lines.length,
    blocks: blocked,
    blocked,
    allows: allowed,
    allowed,
    shadows,
    valid: check.valid,
    top_rules: topRules,
    top_tools: topTools,
    recent,
  };
}

/**
 * Starts a zero-dependency local dashboard at localhost:<port>
 */
function startEvidenceUi(port = 3100, filePath = EVIDENCE_FILE) {
  const server = http.createServer((req, res) => {
    if (req.url === '/api/stats') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(getEvidenceStats(filePath)));
      return;
    }

    if (req.url === '/api/verify') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(verifyEvidenceLedger(filePath)));
      return;
    }

    // Single-page dashboard HTML
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>zn Evidence Engine - Cryptographic AI Audit Ledger</title>
  <style>
    :root {
      --bg: #0b0f19;
      --card: #151c2e;
      --border: #263554;
      --accent: #10b981;
      --danger: #ef4444;
      --text: #f3f4f6;
      --muted: #9ca3af;
      --mono: 'JetBrains Mono', 'Fira Code', monospace;
    }
    body {
      margin: 0;
      padding: 2rem;
      background: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    }
    .container { max-width: 1200px; margin: 0 auto; }
    header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 1.5rem; margin-bottom: 2rem; }
    h1 { margin: 0; font-size: 1.5rem; display: flex; align-items: center; gap: 0.75rem; }
    .status-badge { padding: 0.35rem 0.8rem; border-radius: 9999px; font-size: 0.85rem; font-weight: 600; display: inline-flex; align-items: center; gap: 0.5rem; }
    .badge-valid { background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3); }
    .badge-invalid { background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3); }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 1.25rem; margin-bottom: 2rem; }
    .card { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 1.25rem; }
    .card h3 { margin: 0 0 0.5rem 0; font-size: 0.85rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; }
    .metric { font-size: 2rem; font-weight: 700; }
    table { width: 100%; border-collapse: collapse; background: var(--card); border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }
    th, td { padding: 0.85rem 1rem; text-align: left; border-bottom: 1px solid var(--border); font-size: 0.9rem; }
    th { background: rgba(255, 255, 255, 0.03); color: var(--muted); font-weight: 600; }
    tr:hover { background: rgba(255, 255, 255, 0.02); }
    .mono { font-family: var(--mono); font-size: 0.82rem; }
    .tag { padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; }
    .tag-block { background: rgba(239, 68, 68, 0.2); color: #fca5a5; }
    .tag-allow { background: rgba(16, 185, 129, 0.2); color: #6ee7b7; }
    .tag-shadow { background: rgba(245, 158, 11, 0.2); color: #fcd34d; }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1><span>🛡️</span> zn Evidence Engine Dashboard</h1>
      <div id="integrity-badge" class="status-badge badge-valid">● SHA-256 Ledger Verified</div>
    </header>

    <div class="grid">
      <div class="card">
        <h3>Total Audit Events</h3>
        <div class="metric" id="m-total">-</div>
      </div>
      <div class="card">
        <h3>Threats Intercepted</h3>
        <div class="metric" style="color: var(--danger);" id="m-blocks">-</div>
      </div>
      <div class="card">
        <h3>Operations Allowed</h3>
        <div class="metric" style="color: var(--accent);" id="m-allows">-</div>
      </div>
      <div class="card">
        <h3>Shadow Alerts</h3>
        <div class="metric" style="color: #f59e0b;" id="m-shadows">-</div>
      </div>
    </div>

    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
      <h2 style="margin: 0; font-size: 1.15rem;">Recent Security Records (SHA-256 Chained)</h2>
      <span style="color: var(--muted); font-size: 0.85rem;">Live polling every 3s</span>
    </div>

    <table>
      <thead>
        <tr>
          <th>Timestamp</th>
          <th>Verdict</th>
          <th>Tool & Environment</th>
          <th>Rule / Detail</th>
          <th>Payload Hash</th>
          <th>Latency</th>
        </tr>
      </thead>
      <tbody id="audit-table">
        <tr><td colspan="6" style="text-align:center; color: var(--muted); padding: 2rem;">Loading evidence ledger...</td></tr>
      </tbody>
    </table>
  </div>

  <script>
    async function fetchData() {
      try {
        const [statsRes, verifyRes] = await Promise.all([
          fetch('/api/stats'),
          fetch('/api/verify')
        ]);
        const d = await statsRes.json();
        const v = await verifyRes.json();

        document.getElementById('m-total').textContent = d.total || 0;
        document.getElementById('m-blocks').textContent = d.blocks || 0;
        document.getElementById('m-allows').textContent = d.allows || 0;
        document.getElementById('m-shadows').textContent = d.shadows || 0;

        const badge = document.getElementById('integrity-badge');
        if (v.valid) {
          badge.className = 'status-badge badge-valid';
          badge.textContent = '● SHA-256 Chain Verified (Tamper-Free)';
        } else {
          badge.className = 'status-badge badge-invalid';
          badge.textContent = '✖ TAMPER DETECTED at record ' + v.broken_index;
        }

        const tbody = document.getElementById('audit-table');
        if (!d.recent || d.recent.length === 0) {
          tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; color: var(--muted); padding: 2rem;">No evidence records logged yet. Run an MCP tool call to see live data.</td></tr>';
          return;
        }

        tbody.innerHTML = d.recent.map(r => {
          const isBlock = r.verdict === 'block';
          const isShadow = r.verdict === 'shadow';
          const tagClass = isBlock ? 'tag-block' : (isShadow ? 'tag-shadow' : 'tag-allow');
          return '<tr>' +
            '<td class="mono">' + (r.timestamp || '').replace('T', ' ').slice(0, 19) + '</td>' +
            '<td><span class="tag ' + tagClass + '">' + (r.verdict || 'allow').toUpperCase() + '</span></td>' +
            '<td><strong>' + (r.tool_name || 'call') + '</strong> <span style="color:var(--muted); font-size:0.8rem;">(' + (r.agent_environment || 'agent') + ')</span></td>' +
            '<td>' + (r.rule || r.reason || '<span style="color:var(--muted);">-</span>') + '</td>' +
            '<td class="mono" title="' + (r.payload_sha256 || '') + '">' + (r.payload_sha256 || '').slice(0, 12) + '...</td>' +
            '<td class="mono">' + (r.latency_us ? r.latency_us + ' µs' : '< 1 ms') + '</td>' +
          '</tr>';
        }).join('');
      } catch (err) {
        console.error('Failed fetching data:', err);
      }
    }
    fetchData();
    setInterval(fetchData, 3000);
  </script>
</body>
</html>`);
  });

  server.listen(port, () => {
    process.stdout.write(`
🛡️  zn Evidence Engine Dashboard running at http://localhost:${port}
Ledger location: ${filePath}
Press Ctrl+C to stop dashboard.
\n`);
  });
}

module.exports = {
  logEvidence,
  verifyEvidenceLedger,
  getEvidenceStats,
  startEvidenceUi,
  EVIDENCE_FILE,
  GENESIS_HASH,
};
