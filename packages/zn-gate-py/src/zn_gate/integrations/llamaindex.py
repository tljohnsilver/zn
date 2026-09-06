"""
LlamaIndex query and tool protection for zn-gate.
"""
from __future__ import annotations
from typing import Any

from ..guard import GuardBlockError
from ..rules import evaluate, sanitize_tool_result


class ZnLlamaGuard:
    """
    Query and tool pre-check for LlamaIndex query engines and agents.
    """
    def __init__(self, on_block: str = "raise", mask_secrets: bool = True, raise_on_violation: Optional[bool] = None):
        if raise_on_violation is not None:
            self.on_block = "raise" if raise_on_violation else "ignore"
        else:
            self.on_block = on_block
        self.mask_secrets = mask_secrets

    def check_query(self, query_str: str) -> str:
        assessment = evaluate(query_str)
        if not assessment.allowed:
            if self.on_block == "raise":
                raise GuardBlockError(assessment, target="llamaindex:query", payload=query_str)
        return query_str

    def on_query_start(self, query_str: str) -> str:
        return self.check_query(query_str)

    def sanitize_response(self, response: Any) -> Any:
        if self.mask_secrets:
            clean, _ = sanitize_tool_result(response)
            return clean
        return response
