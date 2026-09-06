'use strict';

const { spawn } = require('child_process');
const readline = require('readline');
const { analyze, checkToolResult } = require('./client');
const { logEvidence } = require('./evidence');

/**
 * Starts an MCP Security Shield proxy over stdio.
 * Intercepts JSON-RPC 2.0 messages between the client (stdin/stdout)
 * and the wrapped MCP server (child process).
 *
 * Provides three layers of protection:
 * 1. Tool Poisoning Protection: Inspects `tools/list` responses for adversarial prompts
 *    in tool descriptions and parameter schemas before the LLM ingests them.
 * 2. Pre-flight Request Protection: Intercepts `tools/call` requests and blocks malicious arguments.
 * 3. Post-flight Response Protection: Intercepts tool execution outputs and neutralizes indirect prompt injections.
 *
 * @param {string} command - The target MCP executable (e.g. 'uvx', 'npx', 'node', 'python')
 * @param {string[]} args - Arguments passed to the target MCP executable
 * @param {object} [options] - Options (apiKey, stage, verbose, localOnly, shadow, agent)
 */
function startMcpShield(command, args, options = {}) {
  const verbose = options.verbose || false;
  const log = (...msg) => {
    if (verbose) {
      process.stderr.write(`[zn-shield] ${msg.join(' ')}\n`);
    }
  };

  log(`Spawning wrapped MCP server: ${command} ${args.join(' ')}`);

  const child = spawn(command, args, {
    stdio: ['pipe', 'pipe', 'inherit'],
    env: process.env,
  });

  child.on('error', (err) => {
    process.stderr.write(`[zn-shield ERROR] Failed to start wrapped server '${command}': ${err.message}\n`);
    process.exit(1);
  });

  child.on('exit', (code, signal) => {
    log(`Wrapped server exited with code=${code} signal=${signal}`);
    process.exit(code !== null ? code : 1);
  });

  // Keep track of pending requests to correlate with responses
  // id -> { method, toolName, startTime }
  const pendingCalls = new Map();

  // 1. Read from client (process.stdin) -> inspect requests -> send to child.stdin
  const clientRl = readline.createInterface({
    input: process.stdin,
    terminal: false,
  });

  clientRl.on('line', async (line) => {
    line = line.trim();
    if (!line) return;

    let msg;
    try {
      msg = JSON.parse(line);
    } catch {
      // Non-JSON line, forward as-is
      child.stdin.write(line + '\n');
      return;
    }

    // Intercept tools/list requests: track ID to scan responses for tool poisoning
    if (msg && msg.method === 'tools/list') {
      const callId = msg.id;
      log(`Tracking tools/list request [${callId}] for tool poisoning inspection`);
      pendingCalls.set(callId, {
        method: 'tools/list',
        startTime: Date.now(),
      });
    }

    // Intercept tool calls: method === "tools/call"
    if (msg && msg.method === 'tools/call') {
      const callId = msg.id;
      const toolName = msg.params?.name || 'unknown_tool';
      const toolArgs = msg.params?.arguments || {};
      const argsText = typeof toolArgs === 'string' ? toolArgs : JSON.stringify(toolArgs);

      log(`Intercepting request tools/call [${callId}]: tool=${toolName}`);

      // Inspect tool arguments for injection / exfiltration attempts
      const check = await analyze(argsText, options);
      if (check.verdict === 'block') {
        const ruleName = check.rule || check.reason || 'prompt_injection';
        process.stderr.write(`[zn-shield BLOCKED REQUEST] Prompt injection detected in arguments for tool '${toolName}'. Rule: ${ruleName}\n`);

        logEvidence({
          agent: options.agent || 'mcp-client',
          phase: 'tool-call',
          tool_name: toolName,
          payload: argsText,
          verdict: 'block',
          rule: ruleName,
          reason: check.reason,
          confidence: check.confidence || 0.99,
          latency_us: check.latency_us || 12,
          engine: check.engine || 'oss-deterministic',
        });

        if (!options.shadow) {
          // Return JSON-RPC error response directly to client WITHOUT invoking child process
          const blockedResponse = {
            jsonrpc: '2.0',
            id: callId,
            result: {
              content: [
                {
                  type: 'text',
                  text: `[zn-gate SECURITY BLOCKED] Tool invocation rejected: potential prompt injection or unauthorized payload detected in tool arguments (${ruleName}).`,
                },
              ],
              isError: true,
            },
          };
          process.stdout.write(JSON.stringify(blockedResponse) + '\n');
          return;
        } else {
          log(`[zn-shield SHADOW] Request would be blocked, but forwarding in shadow mode.`);
        }
      } else {
        logEvidence({
          agent: options.agent || 'mcp-client',
          phase: 'tool-call',
          tool_name: toolName,
          payload: argsText,
          verdict: 'allow',
          latency_us: check.latency_us || 5,
          engine: check.engine || 'oss-deterministic',
        });
      }

      // Record pending call for response checking
      pendingCalls.set(callId, {
        method: 'tools/call',
        toolName,
        startTime: Date.now(),
      });
    }

    // Forward approved request to child process
    child.stdin.write(line + '\n');
  });

  // 2. Read from child (child.stdout) -> inspect responses -> send to process.stdout
  const serverRl = readline.createInterface({
    input: child.stdout,
    terminal: false,
  });

  serverRl.on('line', async (line) => {
    line = line.trim();
    if (!line) return;

    let msg;
    try {
      msg = JSON.parse(line);
    } catch {
      process.stdout.write(line + '\n');
      return;
    }

    // Check if this response corresponds to a tracked request
    if (msg && msg.id !== undefined && pendingCalls.has(msg.id)) {
      const pending = pendingCalls.get(msg.id);
      pendingCalls.delete(msg.id);

      // Handle tools/list response: sanitize tool descriptions and input schemas
      if (pending.method === 'tools/list') {
        const tools = msg.result?.tools;
        if (Array.isArray(tools)) {
          for (const tool of tools) {
            // 1. Inspect tool description
            if (typeof tool.description === 'string' && tool.description.length > 0) {
              const check = await analyze(tool.description, options);
              if (check.verdict === 'block') {
                const ruleName = check.rule || check.reason || 'tool_poisoning';
                process.stderr.write(`[zn-shield BLOCKED TOOL DESCRIPTION] Poisoned tool description in '${tool.name}'. Rule: ${ruleName}\n`);

                logEvidence({
                  agent: options.agent || 'mcp-server',
                  phase: 'tool-definition',
                  tool_name: tool.name,
                  payload: tool.description,
                  verdict: 'block',
                  rule: ruleName,
                  reason: check.reason,
                  confidence: check.confidence || 0.99,
                  latency_us: check.latency_us || 12,
                  engine: check.engine || 'oss-deterministic',
                });

                if (!options.shadow) {
                  tool.description = `[zn-gate SECURITY BLOCKED] Tool description neutralized: unauthorized prompt injection detected (${ruleName}).`;
                }
              }
            }

            // 2. Inspect inputSchema property descriptions
            if (tool.inputSchema && typeof tool.inputSchema === 'object' && tool.inputSchema.properties) {
              const props = tool.inputSchema.properties;
              for (const [propName, propDef] of Object.entries(props)) {
                if (propDef && typeof propDef.description === 'string' && propDef.description.length > 0) {
                  const check = await analyze(propDef.description, options);
                  if (check.verdict === 'block') {
                    const ruleName = check.rule || check.reason || 'parameter_poisoning';
                    process.stderr.write(`[zn-shield BLOCKED PARAMETER DESCRIPTION] Poisoned parameter '${propName}' in tool '${tool.name}'. Rule: ${ruleName}\n`);

                    logEvidence({
                      agent: options.agent || 'mcp-server',
                      phase: 'parameter-definition',
                      tool_name: `${tool.name}.${propName}`,
                      payload: propDef.description,
                      verdict: 'block',
                      rule: ruleName,
                      reason: check.reason,
                      confidence: check.confidence || 0.99,
                      latency_us: check.latency_us || 12,
                      engine: check.engine || 'oss-deterministic',
                    });

                    if (!options.shadow) {
                      propDef.description = `[zn-gate SECURITY BLOCKED] Parameter description neutralized: unauthorized prompt injection detected (${ruleName}).`;
                    }
                  }
                }
              }
            }
          }
        }
      } else {
        // Handle tools/call response
        const toolName = pending.toolName;
        const contentList = msg.result?.content;

        if (Array.isArray(contentList)) {
          let hasBlockedContent = false;
          let blockReason = '';

          for (let i = 0; i < contentList.length; i++) {
            const item = contentList[i];
            if (item.type === 'text' && typeof item.text === 'string') {
              const check = await checkToolResult(toolName, item.text, options);
              const isBlock = check.safe_to_ingest === false || check.assessment?.verdict === 'block' || check.verdict === 'block';
              if (isBlock) {
                hasBlockedContent = true;
                blockReason = check.assessment?.rule || check.assessment?.reason || check.rule || check.reason || 'indirect prompt injection';
                process.stderr.write(`[zn-shield BLOCKED RESPONSE] Indirect prompt injection detected in output of tool '${toolName}'. Rule: ${blockReason}\n`);
                
                logEvidence({
                  agent: options.agent || 'mcp-server',
                  phase: 'tool-result',
                  tool_name: toolName,
                  payload: item.text,
                  verdict: 'block',
                  rule: blockReason,
                  reason: check.assessment?.reason,
                  confidence: check.assessment?.confidence || 0.95,
                  latency_us: check.assessment?.latency_us || 15,
                  engine: check.assessment?.engine || 'oss-deterministic',
                });

                if (!options.shadow) {
                  item.text = check.sanitized_content || `[zn-gate SECURITY BLOCKED] Content neutralized: indirect prompt injection detected in external tool output (${blockReason}).`;
                }
              } else {
                logEvidence({
                  agent: options.agent || 'mcp-server',
                  phase: 'tool-result',
                  tool_name: toolName,
                  payload: item.text,
                  verdict: 'allow',
                  latency_us: check.assessment?.latency_us || 5,
                  engine: check.assessment?.engine || 'oss-deterministic',
                });
              }
            }
          }

          if (hasBlockedContent && msg.result && !options.shadow) {
            msg.result.isError = true;
          }
        }
      }
    }

    // Forward inspected/sanitized response to client
    process.stdout.write(JSON.stringify(msg) + '\n');
  });

  // Handle process termination
  const cleanExit = () => {
    child.kill('SIGTERM');
    setTimeout(() => child.kill('SIGKILL'), 2000).unref();
  };
  process.on('SIGINT', cleanExit);
  process.on('SIGTERM', cleanExit);
}

module.exports = { startMcpShield };
