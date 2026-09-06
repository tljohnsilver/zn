'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');

function getKnownEnvironments() {
  const home = os.homedir();
  const isWin = process.platform === 'win32';
  const isMac = process.platform === 'darwin';

  const claudeDesktopPath = isWin
    ? path.join(process.env.APPDATA || path.join(home, 'AppData', 'Roaming'), 'Claude', 'claude_desktop_config.json')
    : isMac
    ? path.join(home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json')
    : path.join(home, 'config', 'Claude', 'claude_desktop_config.json');

  return [
    {
      name: 'Claude Desktop',
      id: 'claude-desktop',
      filePath: claudeDesktopPath,
      key: 'mcpServers',
    },
    {
      name: 'Claude Code',
      id: 'claude-code',
      filePath: path.join(home, '.claude.json'),
      key: 'mcpServers',
    },
    {
      name: 'Cursor',
      id: 'cursor',
      filePath: path.join(home, '.cursor', 'mcp.json'),
      key: 'mcpServers',
    },
    {
      name: 'Antigravity (AGY)',
      id: 'antigravity',
      filePath: path.join(home, '.gemini', 'antigravity', 'mcp.json'),
      key: 'mcpServers',
    },
    {
      name: 'Codex',
      id: 'codex',
      filePath: path.join(home, '.codex', 'config.json'),
      key: 'mcpServers',
    },
    {
      name: 'OpenCode',
      id: 'opencode',
      filePath: path.join(home, '.local', 'share', 'opencode', 'mcp.json'),
      key: 'mcpServers',
    },
    {
      name: 'Hermes / PiAgent',
      id: 'hermes-piagent',
      filePath: path.join(home, '.hermes', 'mcp.json'),
      key: 'mcpServers',
    },
  ];
}

/**
 * Scans the filesystem for any of the 7 supported agent environments.
 */
function scanEnvironments(customEnvList = null) {
  const envs = customEnvList || getKnownEnvironments();
  const results = [];

  for (const env of envs) {
    const exists = fs.existsSync(env.filePath);
    let servers = [];
    let isShielded = false;

    if (exists) {
      try {
        const raw = fs.readFileSync(env.filePath, 'utf8');
        const json = JSON.parse(raw);
        const srvs = json[env.key] || {};
        for (const [sName, sCfg] of Object.entries(srvs)) {
          const cmd = sCfg.command || '';
          const args = (sCfg.args || []).join(' ');
          const shielded = cmd.includes('zn-gate') || cmd.includes('zn-mcp') || args.includes('shield');
          if (shielded) isShielded = true;
          servers.push({
            name: sName,
            command: cmd,
            args: sCfg.args || [],
            shielded,
          });
        }
      } catch (e) {
        servers = [{ name: 'error', error: e.message }];
      }
    }

    results.push({
      ...env,
      exists,
      servers,
      serverCount: servers.filter(s => !s.error).length,
      allShielded: servers.length > 0 && servers.every(s => s.shielded),
    });
  }

  return results;
}

/**
 * Protects (or reverts) the detected environments.
 *
 * @param {object} options - { shadow: boolean, dryRun: boolean, revert: boolean, envList: array }
 */
function configureEnvironments(options = {}) {
  const envs = scanEnvironments(options.envList);
  const actions = [];

  for (const env of envs) {
    if (!env.exists || env.serverCount === 0) continue;

    if (options.revert) {
      // Find latest .bak file
      const dir = path.dirname(env.filePath);
      const base = path.basename(env.filePath);
      const baks = fs.readdirSync(dir)
        .filter(f => f.startsWith(base + '.bak.'))
        .sort()
        .reverse();

      if (baks.length > 0) {
        const latestBak = path.join(dir, baks[0]);
        if (!options.dryRun) {
          fs.copyFileSync(latestBak, env.filePath);
        }
        actions.push({
          env: env.name,
          status: 'reverted',
          from: latestBak,
        });
      } else {
        actions.push({
          env: env.name,
          status: 'no_backup_found',
        });
      }
      continue;
    }

    // Shielding mode
    try {
      const raw = fs.readFileSync(env.filePath, 'utf8');
      const json = JSON.parse(raw);
      const srvs = json[env.key] || {};
      let modified = false;

      for (const [sName, sCfg] of Object.entries(srvs)) {
        const cmd = sCfg.command || '';
        const args = sCfg.args || [];
        const isShielded = cmd.includes('zn-gate') || cmd.includes('zn-mcp') || args.join(' ').includes('shield');

        if (!isShielded) {
          const originalCmd = sCfg.command;
          const originalArgs = sCfg.args || [];

          // Rewriting command to wrap with zn-gate shield
          sCfg.command = 'npx';
          const shieldArgs = ['-y', 'zn-gate', 'shield'];
          if (options.shadow) {
            shieldArgs.push('--shadow');
          }
          shieldArgs.push('--', originalCmd, ...originalArgs);
          sCfg.args = shieldArgs;
          modified = true;
        }
      }

      if (modified) {
        if (!options.dryRun) {
          // 1. Create backup
          const bakPath = `${env.filePath}.bak.${Date.now()}`;
          fs.writeFileSync(bakPath, raw, 'utf8');
          // 2. Write protected configuration
          fs.writeFileSync(env.filePath, JSON.stringify(json, null, 2) + '\n', 'utf8');
        }
        actions.push({
          env: env.name,
          status: options.dryRun ? 'would_shield' : 'shielded',
          serversCount: env.serverCount,
          shadow: Boolean(options.shadow),
        });
      } else {
        actions.push({
          env: env.name,
          status: 'already_shielded',
        });
      }
    } catch (err) {
      actions.push({
        env: env.name,
        status: 'error',
        error: err.message,
      });
    }
  }

  return { scanned: envs, actions };
}

module.exports = {
  getKnownEnvironments,
  scanEnvironments,
  configureEnvironments,
};
