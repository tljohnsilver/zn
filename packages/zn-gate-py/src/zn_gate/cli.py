"""
CLI entrypoint for zn-gate.
Pure Python stdlib.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from .rules import RULES_VERSION, evaluate


def cmd_test(args: argparse.Namespace) -> int:
    text = args.text
    t0 = time.perf_counter()
    assessment = evaluate(text)
    latency_us = (time.perf_counter() - t0) * 1_000_000

    if args.json:
        out = assessment.to_dict()
        out["latency_us"] = round(latency_us, 2)
        print(json.dumps(out, indent=2))
    else:
        status_icon = "🛡️ ALLOW" if assessment.allowed else "🚨 BLOCK"
        print(f"\n{status_icon} | Verdict: {assessment.verdict.upper()} (latency: {latency_us:.1f}µs)")
        print(f"Rule:       {assessment.rule}")
        if assessment.reason:
            print(f"Reason:     {assessment.reason}")
        print(f"Confidence: {assessment.confidence * 100:.1f}%")
        print(f"Engine:     {assessment.engine} (rules: {assessment.rules_version})\n")

    return 0 if assessment.allowed else 1


def cmd_analyze(args: argparse.Namespace) -> int:
    path = Path(args.file)
    if not path.exists():
        print(f"Error: file not found: {path}", file=sys.stderr)
        return 2

    content = path.read_text(encoding="utf-8", errors="ignore")
    lines = content.splitlines()
    violations = []

    for i, line in enumerate(lines, 1):
        if not line.strip():
            continue
        res = evaluate(line)
        if not res.allowed:
            violations.append({"line": i, "content": line.strip()[:120], "assessment": res.to_dict()})

    if args.json:
        print(json.dumps({"file": str(path), "total_lines": len(lines), "violations": violations}, indent=2))
    else:
        print(f"\nScanning: {path} ({len(lines)} lines)")
        if not violations:
            print("✅ Clean! No prompt injection or sensitive exfiltration vectors found.\n")
            return 0
        print(f"⚠️  Found {len(violations)} potential threat vectors:\n")
        for v in violations:
            print(f"  Line {v['line']}: [{v['assessment']['rule']}] {v['assessment']['reason']}")
            print(f"    Snippet: {v['content']}\n")
    return 1 if violations else 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="zn-gate",
        description="zn deterministic guardrail engine for AI agents and LLM tool calling."
    )
    parser.add_argument("--version", action="version", version=f"zn-gate 1.2.2 (rules: {RULES_VERSION})")
    subparsers = parser.add_subparsers(dest="command", help="Sub-commands")

    # test command
    test_parser = subparsers.add_parser("test", help="Test a single text payload against guardrail rules")
    test_parser.add_argument("text", help="Prompt or tool argument string to test")
    test_parser.add_argument("--json", action="store_true", help="Output results as JSON")

    # analyze command
    analyze_parser = subparsers.add_parser("analyze", help="Analyze a prompt file or dataset for threat vectors")
    analyze_parser.add_argument("file", help="File to scan")
    analyze_parser.add_argument("--json", action="store_true", help="Output results as JSON")

    args = parser.parse_args()
    if args.command == "test":
        return cmd_test(args)
    elif args.command == "analyze":
        return cmd_analyze(args)
    else:
        parser.print_help()
        return 0


if __name__ == "__main__":
    sys.exit(main())
