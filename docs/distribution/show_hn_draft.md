# Show HN: zn-gate – 1-Click Zero-Touch Security Shield & Cryptographic Audit for Cursor, Claude Code, and MCP

**URL**: https://github.com/tljohnsilver/zn
**Homepage**: https://usezn.com
**NPM**: `npx -y zn-gate init`

Hey HN,

Over the past year building autonomous agent workflows, we ran into the same security wall that many in the community have voiced recently: when an AI coding assistant (Cursor, Claude Code, Codex) has access to your shell, database, filesystem, and external APIs via MCP, **a single indirect prompt injection in a web scrape, SQL query, or git diff can lead to arbitrary code execution, SSH key dumps, or covert markdown data exfiltration.**

Most existing AI guardrails make two major tradeoffs:
1. **The Latency Tax**: They require routing every tool argument and tool output through a remote cloud API, adding 200–400ms per step. In an agent loop with 10 tool calls, that's 3–4 seconds of pure lag.
2. **The Adoption Barrier**: They require manually rewriting config files, maintaining custom proxies, or deploying heavy Kubernetes containers.
3. **The Audit Gap**: When compliance teams ask for SOC 2, ISO 27001, or EU AI Act proof of what tools executed, flat log files on disk can be easily deleted or tampered with.

To solve this, we built **zn-gate** (v1.3.0) — a zero-trust, local-first security firewall designed specifically for the Model Context Protocol and AI coding agents.

### Key Features

1. **1-Click Auto-Shield (`npx -y zn-gate init`)**:
   Runs across 7 agent environments (**Claude Desktop**, **Claude Code**, **Cursor**, **Antigravity**, **Codex**, **OpenCode**, and **Hermes / PiAgent**). It scans your existing config files, creates timestamped atomic backups (`.bak.<timestamp>`), and wraps your stdio MCP servers in an inspecting proxy.
   Supports `--shadow` (monitor mode), `--dry-run`, and `--revert`.

2. **Sub-Millisecond Fast-Path (< 0.2 ms / 167k ops/sec)**:
   Deterministic regex and normalization rules run directly in-process on CPU, keeping security off your agent's critical latency path. Direct injections, shell exfiltration, and markdown tracking pixels are dropped in microseconds with 0 network latency.

3. **100% Offline / Air-Gapped Hybrid Neural Engine**:
   For semantic deep attacks, we quantize fine-tuned neural weights to INT8 ONNX running locally on CPU with AVX-512 VNNI (25.28 ms). Zero tool calls, credentials, or code ever leave your machine.

4. **Cryptographic Evidence Engine (`zn-gate evidence --ui`)**:
   Every inspection decision is logged into an immutable SHA-256 hash-chained ledger (`~/.zn/evidence.jsonl`):
   `hash_n = SHA-256(hash_{n-1} + ":" + JSON(record_n))`
   Run `zn-gate evidence --verify` to mathematically verify the entire history from genesis (flags any retroactive tampering instantly), or `zn-gate evidence --ui` to open a zero-dependency local dashboard at `localhost:3100`.

5. **Bidirectional Stdio Proxy (`zn-gate shield -- <cmd> <args>`)**:
   Inspects outgoing tool arguments pre-flight, and sanitizes tool outputs post-flight before context assimilation.

### Try it now:

```bash
# Auto-shield all your agent configs in 3 seconds:
npx -y zn-gate init

# Run the 33-vector self-test benchmark:
npx -y zn-gate test

# Launch the cryptographic audit dashboard:
npx -y zn-gate evidence --ui
```

Everything is 100% open source under the MIT license. We'd love your feedback on the stdio wrapping approach and what attack vectors you'd like to see in our benchmark suite!

GitHub: https://github.com/tljohnsilver/zn
