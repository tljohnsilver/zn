"""
Promptfoo custom provider integration for zn-gate.
Enables automated red-teaming and prompt-injection benchmarking via Promptfoo.

Usage in promptfooconfig.yaml:
providers:
  - id: 'python:zn_gate.integrations.promptfoo:call_api'
    label: 'zn-gate deterministic guardrail'
"""
from __future__ import annotations
import time
from typing import Any, Dict, Optional

from ..rules import evaluate


def call_api(prompt: str, options: Optional[Dict[str, Any]] = None, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Standard Promptfoo Python provider entrypoint.
    Receives prompt, runs zn-gate evaluation, returns standard response structure.
    """
    options = options or {}
    t0 = time.perf_counter()
    assessment = evaluate(prompt)
    latency_ms = (time.perf_counter() - t0) * 1000

    if not assessment.allowed:
        output_text = f"[BLOCKED] rule={assessment.rule} reason={assessment.reason} confidence={assessment.confidence}"
    else:
        output_text = f"[ALLOWED] clean (confidence={assessment.confidence})"

    return {
        "output": output_text,
        "tokenUsage": {
            "total": 0,
            "prompt": 0,
            "completion": 0,
        },
        "cost": 0.0,
        "cached": False,
        "metadata": {
            "verdict": assessment.verdict,
            "rule": assessment.rule,
            "reason": assessment.reason,
            "confidence": assessment.confidence,
            "latency_ms": round(latency_ms, 3),
            "allowed": assessment.allowed,
        }
    }
