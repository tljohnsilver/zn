'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { logEvidence, verifyEvidenceLedger, getEvidenceStats } = require('../lib/evidence');

test('evidence engine - appends cryptographically chained records', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'zn-ev-test-'));
  const testLedger = path.join(tmpDir, 'evidence.jsonl');

  try {
    const rec1 = logEvidence({
      agent: 'claude-code',
      phase: 'tool-call',
      tool_name: 'bash',
      payload: 'cat ~/.ssh/id_rsa',
      verdict: 'block',
      rule: 'LFI_SSH_PATTERN',
      latency_us: 25,
      engine: 'oss-hybrid'
    }, testLedger);

    assert.equal(rec1.prev_hash, '0'.repeat(64));
    assert.ok(rec1.record_hash && rec1.record_hash.length === 64);
    assert.equal(rec1.verdict, 'block');

    const rec2 = logEvidence({
      agent: 'cursor',
      phase: 'tool-result',
      tool_name: 'postgres',
      payload: 'SELECT 1',
      verdict: 'allow',
      rule: null,
      latency_us: 10,
      engine: 'oss-deterministic'
    }, testLedger);

    assert.equal(rec2.prev_hash, rec1.record_hash);
    assert.ok(rec2.record_hash && rec2.record_hash.length === 64);

    const stats = getEvidenceStats(testLedger);
    assert.equal(stats.total, 2);
    assert.equal(stats.blocks, 1);
    assert.equal(stats.allows, 1);

    const check = verifyEvidenceLedger(testLedger);
    assert.equal(check.valid, true);
    assert.equal(check.total, 2);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('evidence engine - detects any data tampering in ledger lines', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'zn-ev-tamper-'));
  const testLedger = path.join(tmpDir, 'evidence.jsonl');

  try {
    logEvidence({ agent: 'a', tool_name: 't1', verdict: 'block', rule: 'R1' }, testLedger);
    logEvidence({ agent: 'b', tool_name: 't2', verdict: 'allow', rule: null }, testLedger);
    logEvidence({ agent: 'c', tool_name: 't3', verdict: 'block', rule: 'R2' }, testLedger);

    // Initial verify
    const initialCheck = verifyEvidenceLedger(testLedger);
    assert.equal(initialCheck.valid, true);
    assert.equal(initialCheck.total, 3);

    // Tamper with record 0 (first record verdict changed from block to allow)
    const raw = fs.readFileSync(testLedger, 'utf8').trim().split('\n');
    const parsed1 = JSON.parse(raw[0]);
    parsed1.verdict = 'allow'; // Malicious modification
    raw[0] = JSON.stringify(parsed1);
    fs.writeFileSync(testLedger, raw.join('\n') + '\n', 'utf8');

    // Re-verify: must detect tamper!
    const tamperedCheck = verifyEvidenceLedger(testLedger);
    assert.equal(tamperedCheck.valid, false);
    assert.equal(tamperedCheck.broken_index, 0);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
