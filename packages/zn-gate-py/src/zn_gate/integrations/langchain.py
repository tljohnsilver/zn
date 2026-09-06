"""
LangChain and LangGraph integration for zn-gate.
Zero hard dependencies on langchain.
"""
from __future__ import annotations
from typing import Any, Dict, List, Optional
from uuid import UUID

from ..guard import GuardBlockError, check_tool_call, check_tool_result
from ..rules import Assessment, sanitize_tool_result

try:
    from langchain_core.callbacks.base import BaseCallbackHandler
except ImportError:
    class BaseCallbackHandler:  # type: ignore
        pass


class ZnGuardCallbackHandler(BaseCallbackHandler):
    """
    LangChain / LangGraph Callback Handler that intercepts prompt injection and sensitive path traversal
    before tool execution, and redacts secrets in tool outputs.
    """
    def __init__(self, on_block: str = "raise", mask_secrets: bool = True, raise_on_injection: Optional[bool] = None):
        if raise_on_injection is not None:
            self.on_block = "raise" if raise_on_injection else "ignore"
        else:
            self.on_block = on_block
        self.mask_secrets = mask_secrets

    def on_tool_start(
        self,
        serialized: Dict[str, Any],
        input_str: str,
        *,
        run_id: Optional[UUID] = None,
        parent_run_id: Optional[UUID] = None,
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        inputs: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> Any:
        tool_name = serialized.get("name", "unknown_tool") if isinstance(serialized, dict) else "unknown_tool"
        target_payload = inputs if inputs is not None else input_str
        assessment = check_tool_call(tool_name, target_payload)
        if not assessment.allowed:
            if self.on_block == "raise":
                raise GuardBlockError(assessment, target=f"langchain:{tool_name}", payload=target_payload)
        return None

    def on_tool_end(
        self,
        output: Any,
        *,
        run_id: Optional[UUID] = None,
        parent_run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> Any:
        if self.mask_secrets:
            sanitized, _ = sanitize_tool_result(output)
            return sanitized
        return output
