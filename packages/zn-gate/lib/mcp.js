'use strict';

const readline = require('readline');
const { analyze, checkToolResult, RULES_VERSION, resolveEndpoint } = require('./client');

const SERVER_NAME = 'zn-gate';
const SERVER_VERSION = '1.2.1';
const PROTOCOL_VERSION = '2024-11-05';

function sendJsonRpc(response) {
  process.stdout.write(JSON.stringify(response) + '\n');
}

function sendResult(id, result) {
  sendJsonRpc({
    jsonrpc: '2.0',
    id,
    result,
  });
}

function sendError(id, code, message, data) {
  sendJsonRpc({
    jsonrpc: '2.0',
    id,
    error: {
      code,
      message,
      ...(data !== undefined ? { data } : {}),
    },
  });
}

const TOOLS = [
  {
    name: 'analyze_prompt',
    description: 'Analyze text, prompt, or agent messages for security threats (prompt injection, jailbreak, credential exfiltration, role hijacking). Returns threat assessment, confidence score, and matched rule.',
    inputSchema: {
      type: 'object',
      properties: {
        text: {
          type: 'string',
          description: 'The user input, system prompt, or external message to inspect.',
        },
      },
      required: ['text'],
    },
  },
  {
    name: 'check_tool_call',
    description: 'Pre-flight safety inspection for tool invocations and arguments before execution. Defends against tool poisoning, argument injection, and unauthorized exfiltration attempts.',
    inputSchema: {
      type: 'object',
      properties: {
        tool_name: {
          type: 'string',
          description: 'The name of the tool to be called (e.g. bash, write_file, execute_sql, send_message).',
        },
        arguments: {
          type: 'object',
          description: 'Parameters/payload object that will be supplied to the tool.',
        },
      },
      required: ['tool_name', 'arguments'],
    },
  },
  {
    name: 'check_tool_result',
    description: 'Post-execution safety inspection for tool outputs and third-party content (web pages, git commits, database queries) before LLM context assimilation. Defends against indirect prompt injection and covert data exfiltration.',
    inputSchema: {
      type: 'object',
      properties: {
        tool_name: {
          type: 'string',
          description: 'The name of the tool that produced the output (e.g. fetch, web_search, read_file).',
        },
        content: {
          type: 'string',
          description: 'The output text, markdown, or JSON payload returned by the tool.',
        },
      },
      required: ['tool_name', 'content'],
    },
  },
  {
    name: 'zn_status',
    description: 'Get current zn-gate status, active engine (local OSS vs cloud v30), rules version, and health.',
    inputSchema: {
      type: 'object',
      properties: {},
    },
  },
];

async function handleRequest(message, options) {
  const { id, method, params } = message;

  switch (method) {
    case 'initialize': {
      return sendResult(id, {
        protocolVersion: PROTOCOL_VERSION,
        capabilities: {
          tools: {},
        },
        serverInfo: {
          name: SERVER_NAME,
          version: SERVER_VERSION,
        },
      });
    }

    case 'notifications/initialized': {
      return;
    }

    case 'ping': {
      return sendResult(id, {});
    }

    case 'tools/list': {
      return sendResult(id, {
        tools: TOOLS,
      });
    }

    case 'tools/call': {
      if (!params || typeof params.name !== 'string') {
        return sendError(id, -32602, 'Invalid params: name is required');
      }

      const toolName = params.name;
      const args = params.arguments || {};

      if (toolName === 'analyze_prompt') {
        const text = typeof args.text === 'string' ? args.text : '';
        const assessment = await analyze(text, options);
        const isBlock = assessment.verdict?.toLowerCase() === 'block';

        return sendResult(id, {
          isError: isBlock,
          content: [
            {
              type: 'text',
              text: JSON.stringify(assessment, null, 2),
            },
          ],
        });
      }

      if (toolName === 'check_tool_call') {
        const targetTool = String(args.tool_name || 'unknown');
        const toolArgs = args.arguments || {};

        const stringValues = [];
        function extractStrings(obj) {
          if (typeof obj === 'string') stringValues.push(obj);
          else if (Array.isArray(obj)) obj.forEach(extractStrings);
          else if (obj && typeof obj === 'object') Object.values(obj).forEach(extractStrings);
        }
        extractStrings(toolArgs);

        let worstAssessment = await analyze(`${targetTool}: ${JSON.stringify(toolArgs)}`, options);
        let isBlock = worstAssessment.verdict?.toLowerCase() === 'block';

        if (!isBlock) {
          for (const str of stringValues) {
            if (str.length >= 4) {
              const subRes = await analyze(str, options);
              if (subRes.verdict?.toLowerCase() === 'block') {
                worstAssessment = subRes;
                isBlock = true;
                break;
              }
            }
          }
        }

        const output = {
          tool_name: targetTool,
          safe_to_execute: !isBlock,
          assessment: worstAssessment,
        };

        return sendResult(id, {
          isError: isBlock,
          content: [
            {
              type: 'text',
              text: JSON.stringify(output, null, 2),
            },
          ],
        });
      }

      if (toolName === 'check_tool_result') {
        const targetTool = String(args.tool_name || 'unknown');
        const rawContent = args.content !== undefined ? (typeof args.content === 'string' ? args.content : JSON.stringify(args.content)) : '';

        const output = await checkToolResult(targetTool, rawContent, options);

        return sendResult(id, {
          isError: !output.safe_to_ingest,
          content: [
            {
              type: 'text',
              text: JSON.stringify(output, null, 2),
            },
          ],
        });
      }

      if (toolName === 'zn_status') {
        const hasKey = Boolean(options.apiKey || process.env.ZN_API_KEY);
        const status = {
          package: `${SERVER_NAME}@${SERVER_VERSION}`,
          engine: hasKey ? 'cloud-fused-gate' : 'oss-local-rules',
          endpoint: hasKey ? resolveEndpoint(options) : 'offline / local-only',
          rules_version: RULES_VERSION,
          neural_ready: hasKey,
          lifecycle_coverage: 'bidirectional (prompt, pre-tool-call, post-tool-result)',
          tip: hasKey ? 'Cloud neural inspection enabled' : 'Running free local OSS rules. Set ZN_API_KEY for neural protection.',
        };
        return sendResult(id, {
          content: [
            {
              type: 'text',
              text: JSON.stringify(status, null, 2),
            },
          ],
        });
      }

      return sendError(id, -32601, `Method or tool '${toolName}' not found`);
    }

    default: {
      if (id !== undefined) {
        return sendError(id, -32601, `Unsupported method: ${method}`);
      }
    }
  }
}

function startMcpServer(options = {}) {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    terminal: false,
  });

  if (process.env.DEBUG || process.env.ZN_VERBOSE) {
    const hasKey = Boolean(options.apiKey || process.env.ZN_API_KEY);
    process.stderr.write(`[zn-gate] MCP server listening on stdio (engine: ${hasKey ? 'cloud' : 'oss-local'})...\n`);
  }

  rl.on('line', async (line) => {
    const trimmed = line.trim();
    if (!trimmed) return;

    try {
      const message = JSON.parse(trimmed);
      await handleRequest(message, options);
    } catch (err) {
      if (process.env.DEBUG) {
        process.stderr.write(`[zn-gate] JSON-RPC parse error: ${err.message}\n`);
      }
      sendJsonRpc({
        jsonrpc: '2.0',
        id: null,
        error: {
          code: -32700,
          message: 'Parse error',
          data: err.message,
        },
      });
    }
  });

  rl.on('close', () => {
    process.exit(0);
  });
}

module.exports = {
  startMcpServer,
  TOOLS,
  SERVER_NAME,
  SERVER_VERSION,
  PROTOCOL_VERSION,
};
