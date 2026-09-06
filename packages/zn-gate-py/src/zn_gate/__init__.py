"""
zn-gate: Deterministic, ultra-fast, zero-dependency guardrail engine for AI agents and LLM tool calling.
"""

from .rules import Assessment, RULES_VERSION, evaluate, normalize_input, redact_secrets, sanitize_tool_result
from .guard import guard, check_tool_call, check_tool_result, GuardBlockError
from .client import analyze, analyze_cloud, resolve_endpoint
from .evidence import log_evidence, verify_evidence_ledger, get_evidence_stats, export_evidence_ledger, GENESIS_HASH

__version__ = "1.3.0"

__all__ = [
    "evaluate",
    "normalize_input",
    "redact_secrets",
    "sanitize_tool_result",
    "Assessment",
    "analyze",
    "analyze_cloud",
    "resolve_endpoint",
    "guard",
    "check_tool_call",
    "check_tool_result",
    "GuardBlockError",
    "log_evidence",
    "verify_evidence_ledger",
    "get_evidence_stats",
    "export_evidence_ledger",
    "GENESIS_HASH",
    "RULES_VERSION",
    "__version__",
]
