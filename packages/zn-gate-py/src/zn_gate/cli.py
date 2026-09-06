"""
CLI entrypoint for zn-gate.
Pure Python stdlib.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

from .rules import RULES_VERSION, evaluate, redact_secrets


def cmd_test(args: argparse.Namespace) -> int:
    text = args.text
    t0 = time.perf_counter()
    assessment = evaluate(text)
    clean_text, secrets = redact_secrets(text)
    latency_us = (time.perf_counter() - t0) * 1_000_000

    if args.json:
        out = assessment.to_dict()
        out["latency_us"] = round(latency_us, 2)
        out["secrets_detected"] = len(secrets)
        if secrets:
            out["redacted_preview"] = clean_text
        print(json.dumps(out, indent=2))
    else:
        status_icon = "🛡️ ALLOW" if assessment.allowed and not secrets else "🚨 BLOCK"
        print(f"\n{status_icon} | Verdict: {assessment.verdict.upper()} (latency: {latency_us:.1f}µs)")
        print(f"Rule:       {assessment.rule}")
        if assessment.reason:
            print(f"Reason:     {assessment.reason}")
        if secrets:
            print(f"DLP Alert:  Found {len(secrets)} sensitive credentials! Redacted: {clean_text}")
        print(f"Confidence: {assessment.confidence * 100:.1f}%")
        print(f"Engine:     {assessment.engine} (rules: {assessment.rules_version})\n")

    return 0 if (assessment.allowed and not secrets) else 1


def _scan_file(file_path: Path) -> List[Dict[str, Any]]:
    violations: List[Dict[str, Any]] = []
    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return []

    lines = content.splitlines()
    for i, line in enumerate(lines, 1):
        if not line.strip():
            continue
        res = evaluate(line)
        if not res.allowed:
            violations.append({
                "file": str(file_path),
                "line": i,
                "rule": res.rule,
                "reason": res.reason or res.rule,
                "type": "injection",
                "content": line.strip()[:100],
            })
        _, secrets = redact_secrets(line)
        if secrets:
            for s in secrets:
                violations.append({
                    "file": str(file_path),
                    "line": i,
                    "rule": s["rule"],
                    "reason": "Exposed credential detected by DLP filter",
                    "type": "secret_leak",
                    "content": line.strip()[:100],
                })
    return violations


def cmd_scan(args: argparse.Namespace) -> int:
    target_path = Path(args.path)
    if not target_path.exists():
        print(f"Error: target path not found: {target_path}", file=sys.stderr)
        return 2

    files_to_scan: List[Path] = []
    skip_dirs = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build", ".eggs"}
    valid_exts = {".txt", ".md", ".json", ".yaml", ".yml", ".py", ".ts", ".js", ".prompt", ".env", ".toml"}

    if target_path.is_file():
        files_to_scan.append(target_path)
    else:
        for root, dirs, files in os.walk(target_path):
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            for f in files:
                p = Path(root) / f
                if p.suffix in valid_exts or p.name.startswith(".env"):
                    files_to_scan.append(p)

    all_violations: List[Dict[str, Any]] = []
    for fp in files_to_scan:
        all_violations.extend(_scan_file(fp))

    fmt = getattr(args, "format", "text")
    if fmt == "github":
        # Emit GitHub Workflow annotation commands
        for v in all_violations:
            print(f"::error file={v['file']},line={v['line']},title=Security Threat ({v['rule']})::{v['reason']} in: {v['content']}")
        print(f"\n[zn-gate] Scanned {len(files_to_scan)} files. Found {len(all_violations)} security threats.")
    elif fmt == "json":
        print(json.dumps({
            "total_files": len(files_to_scan),
            "total_threats": len(all_violations),
            "threats": all_violations
        }, indent=2))
    else:
        print(f"\n🛡️ zn-gate Security Scanner — Scanned {len(files_to_scan)} files")
        if not all_violations:
            print("✅ All scanned prompts, tool definitions, and files are clean!\n")
            return 0
        print(f"🚨 Found {len(all_violations)} threat vectors:\n")
        for v in all_violations:
            print(f"  {v['file']}:{v['line']} [{v['rule']}] {v['reason']}")
            print(f"    Snippet: {v['content']}\n")

    if all_violations and not args.no_fail:
        return 1
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="zn-gate",
        description="zn deterministic guardrail engine for AI agents and LLM tool calling."
    )
    parser.add_argument("--version", action="version", version=f"zn-gate 1.2.3 (rules: {RULES_VERSION})")
    subparsers = parser.add_subparsers(dest="command", help="Sub-commands")

    # test command
    test_parser = subparsers.add_parser("test", help="Test a single text payload against guardrail rules")
    test_parser.add_argument("text", help="Prompt or tool argument string to test")
    test_parser.add_argument("--json", action="store_true", help="Output results as JSON")

    # scan command
    scan_parser = subparsers.add_parser("scan", help="Scan a file or directory for prompt injection and secret leaks")
    scan_parser.add_argument("path", default=".", nargs="?", help="File or directory path to scan (default: current directory)")
    scan_parser.add_argument("--format", choices=["text", "json", "github"], default="text", help="Output format")
    scan_parser.add_argument("--no-fail", action="store_true", help="Do not exit with error code even if threats are found")

    args = parser.parse_args()
    if args.command == "test":
        return cmd_test(args)
    elif args.command in ("scan", "analyze"):
        # backward compatibility: analyze maps to scan
        if not hasattr(args, "format"):
            args.format = "json" if getattr(args, "json", False) else "text"
        if not hasattr(args, "no_fail"):
            args.no_fail = False
        if not hasattr(args, "path") and hasattr(args, "file"):
            args.path = args.file
        return cmd_scan(args)
    else:
        parser.print_help()
        return 0


if __name__ == "__main__":
    sys.exit(main())
