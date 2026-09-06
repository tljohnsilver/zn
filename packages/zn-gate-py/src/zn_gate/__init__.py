"""
zn-gate: Deterministic, ultra-fast, zero-dependency guardrail engine for AI agents and LLM tool calling.
"""

from .rules import Assessment, RULES_VERSION, evaluate, normalize_input, redact_secrets, sanitize_tool_result
from .guard import guard, check_tool_call, check_tool_result, GuardBlockError
from .client import analyze, analyze_cloud, resolve_endpoint

__version__ = "1.2.4"

__all__ = [
    "evaluate",
    "analyze",
    "analyze_cloud",
    "resolve_endpoint",
    "normalize_input",
    "redact_secrets",
    "sanitize_tool_result",
    "Assessment",
    "guard",
    "check_tool_call",
    "check_tool_result",
    "GuardBlockError",
    "RULES_VERSION",
    "__version__",
]
