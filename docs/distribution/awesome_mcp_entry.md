# Awesome MCP Servers Pull Request Entry

### Category: Security & Governance

Add the following entry under the **Security & Governance** (or **Developer Tools**) section:

```markdown
- [zn-gate](https://github.com/tljohnsilver/zn) - Zero-trust prompt injection firewall, stdio security proxy, and cryptographic evidence audit engine for Cursor, Claude Code, and MCP agents. Supports 1-click auto-shielding via `npx zn-gate init` and runs 100% offline with sub-millisecond latency.
```

### Suggested PR Title:
`feat: add zn-gate - Zero-trust security shield and cryptographic audit engine for MCP`

### Suggested PR Description:
```markdown
### Summary
This PR adds [zn-gate](https://github.com/tljohnsilver/zn) to the Security & Governance section.

### Details
- **Repo**: https://github.com/tljohnsilver/zn
- **License**: MIT
- **Features**:
  - `zn-gate init`: 1-click auto-discovery and wrapping of existing MCP servers across 7 agent ecosystems (Claude, Cursor, Codex, OpenCode, Hermes).
  - Stdio JSON-RPC proxy intercepting tool arguments and neutralizing indirect prompt injections in tool outputs.
  - Sub-millisecond local fast-path (< 0.2 ms) with 100% offline air-gapped support.
  - Cryptographic SHA-256 chained audit ledger and local dashboard (`zn-gate evidence --ui`).
```
