'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { getKnownEnvironments, scanEnvironments, configureEnvironments } = require('../lib/init');

test('zn-gate init - getKnownEnvironments returns list of supported agents', () => {
  const envs = getKnownEnvironments();
  assert.ok(envs.length >= 7);
  const ids = envs.map(e => e.id);
  assert.ok(ids.includes('claude-desktop'));
  assert.ok(ids.includes('cursor'));
  assert.ok(ids.includes('opencode'));
});

test('zn-gate init - scanEnvironments detects active MCP configs', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'zn-init-scan-'));
  const testClaude = path.join(tmpDir, 'claude.json');
  fs.writeFileSync(testClaude, JSON.stringify({
    mcpServers: {
      fetch: { command: 'uvx', args: ['mcp-server-fetch'] }
    }
  }, null, 2));

  try {
    const mockList = [
      { name: 'Claude Desktop', id: 'claude-desktop', filePath: testClaude, key: 'mcpServers' },
      { name: 'Nonexistent', id: 'fake', filePath: path.join(tmpDir, 'no.json'), key: 'mcpServers' }
    ];

    const results = scanEnvironments(mockList);
    assert.equal(results.length, 2);

    const found = results.find(r => r.id === 'claude-desktop');
    assert.equal(found.exists, true);
    assert.equal(found.serverCount, 1);
    assert.equal(found.allShielded, false);

    const missing = results.find(r => r.id === 'fake');
    assert.equal(missing.exists, false);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('zn-gate init - configureEnvironments dryRun does not alter configs', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'zn-init-dry-'));
  const testClaude = path.join(tmpDir, 'claude.json');
  fs.writeFileSync(testClaude, JSON.stringify({
    mcpServers: {
      fetch: { command: 'uvx', args: ['mcp-server-fetch'] }
    }
  }, null, 2));

  try {
    const mockList = [
      { name: 'Claude Desktop', id: 'claude-desktop', filePath: testClaude, key: 'mcpServers' }
    ];

    const { actions } = configureEnvironments({ envList: mockList, dryRun: true });
    assert.equal(actions.length, 1);
    assert.equal(actions[0].status, 'would_shield');

    // Confirm file was untouched
    const after = JSON.parse(fs.readFileSync(testClaude, 'utf8'));
    assert.equal(after.mcpServers.fetch.command, 'uvx');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('zn-gate init - configureEnvironments wraps servers with zn-gate shield and creates backup', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'zn-init-wrap-'));
  const testClaude = path.join(tmpDir, 'claude.json');
  fs.writeFileSync(testClaude, JSON.stringify({
    mcpServers: {
      fetch: { command: 'uvx', args: ['mcp-server-fetch'] }
    }
  }, null, 2));

  try {
    const mockList = [
      { name: 'Claude Desktop', id: 'claude-desktop', filePath: testClaude, key: 'mcpServers' }
    ];

    const { actions } = configureEnvironments({ envList: mockList });
    assert.equal(actions.length, 1);
    assert.equal(actions[0].status, 'shielded');

    const updated = JSON.parse(fs.readFileSync(testClaude, 'utf8'));
    assert.equal(updated.mcpServers.fetch.command, 'npx');
    assert.ok(updated.mcpServers.fetch.args.includes('shield'));

    // Check backup was created
    const files = fs.readdirSync(tmpDir);
    const backupFile = files.find(f => f.includes('bak'));
    assert.ok(backupFile, 'Backup file should exist');

    // Revert test
    const revertRes = configureEnvironments({ envList: mockList, revert: true });
    assert.equal(revertRes.actions[0].status, 'reverted');

    const reverted = JSON.parse(fs.readFileSync(testClaude, 'utf8'));
    assert.equal(reverted.mcpServers.fetch.command, 'uvx');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
