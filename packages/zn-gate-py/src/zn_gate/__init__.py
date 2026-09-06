"""
zn-gate: Deterministic, ultra-fast, zero-dependency guardrail engine for AI agents and LLM tool calling.
"""

from .rules import Assessment, RULES_VERSION, evaluate, normalize_input
from .guard import guard, check_tool_call, check_tool_result, GuardBlockError

__version__ = "1.2.2"

__all__ = [
    "evaluate",
    "normalize_input",
    "Assessment",
    "guard",
    "check_tool_call",
    "check_tool_result",
    "GuardBlockError",
    "RULES_VERSION",
    "__version__",
]
