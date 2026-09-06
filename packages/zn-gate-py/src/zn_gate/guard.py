"""
zn guardrail decorator and tool-call checkers for AI agents and LLM applications.
Pure Python stdlib. Zero external dependencies.
"""

from __future__ import annotations

import asyncio
import functools
import inspect
from typing import Any, Callable, Dict, List, Optional, Union

from .rules import Assessment, evaluate


class GuardBlockError(PermissionError):
    """Raised when an LLM tool call or input is blocked by zn-gate."""
    def __init__(self, assessment: Assessment, target: str = "", payload: Any = None):
        super().__init__(
            f"[zn-gate] Blocked execution on '{target}': {assessment.reason or assessment.rule} (rule: {assessment.rule}, confidence: {assessment.confidence})"
        )
        self.assessment = assessment
        self.target = target
        self.payload = payload


def _extract_strings(data: Any, max_depth: int = 10) -> List[str]:
    """Recursively extract all strings from nested structures."""
    if max_depth <= 0:
        return []

    strings: List[str] = []
    if isinstance(data, str):
        strings.append(data)
    elif isinstance(data, dict):
        for k, v in data.items():
            if isinstance(k, str):
                strings.append(k)
            strings.extend(_extract_strings(v, max_depth - 1))
    elif isinstance(data, (list, tuple, set)):
        for item in data:
            strings.extend(_extract_strings(item, max_depth - 1))
    return strings


def check_tool_call(tool_name: str, arguments: Any = None) -> Assessment:
    """
    Evaluates whether an agent tool call is safe to execute.
    Inspects tool arguments recursively for injection, evasion, or exfiltration attacks.
    """
    strings_to_check = _extract_strings(arguments)
    for s in strings_to_check:
        res = evaluate(s)
        if not res.allowed:
            return res
    return Assessment(verdict="allow", confidence=1.0, rule="none", reason=None)


def check_tool_result(result: Any) -> Assessment:
    """
    Evaluates data returned by external tools (e.g. web search, file content, DB queries)
    for indirect prompt injections or leaked credentials.
    """
    strings_to_check = _extract_strings(result)
    for s in strings_to_check:
        res = evaluate(s)
        if not res.allowed:
            return res
    return Assessment(verdict="allow", confidence=1.0, rule="none", reason=None)


def guard(
    on_block: str = "raise",
    fallback: Any = None,
    check_args: bool = True,
    check_result: bool = False,
    callback: Optional[Callable[[Assessment, str, Any], None]] = None
) -> Callable:
    """
    Decorator for Python functions and agent tools.

    Parameters:
    - on_block: "raise" (default) raises GuardBlockError,
                "return" returns `fallback` (or the Assessment if fallback is None),
                "custom" calls `callback`.
    - fallback: Value to return if on_block="return".
    - check_args: Whether to inspect input arguments (default True).
    - check_result: Whether to inspect function return value (default False).
    - callback: Optional hook called on block: callback(assessment, func_name, payload).
    """
    def decorator(func: Callable) -> Callable:
        func_name = getattr(func, "__name__", "anonymous")

        if inspect.iscoroutinefunction(func):
            @functools.wraps(func)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                if check_args:
                    combined_args = {"args": args, "kwargs": kwargs}
                    assessment = check_tool_call(func_name, combined_args)
                    if not assessment.allowed:
                        if callback:
                            callback(assessment, func_name, combined_args)
                        if on_block == "raise":
                            raise GuardBlockError(assessment, target=func_name, payload=combined_args)
                        elif on_block == "return":
                            return fallback if fallback is not None else assessment

                res = await func(*args, **kwargs)

                if check_result:
                    res_assessment = check_tool_result(res)
                    if not res_assessment.allowed:
                        if callback:
                            callback(res_assessment, func_name, res)
                        if on_block == "raise":
                            raise GuardBlockError(res_assessment, target=f"{func_name}:result", payload=res)
                        elif on_block == "return":
                            return fallback if fallback is not None else res_assessment

                return res
            return async_wrapper
        else:
            @functools.wraps(func)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                if check_args:
                    combined_args = {"args": args, "kwargs": kwargs}
                    assessment = check_tool_call(func_name, combined_args)
                    if not assessment.allowed:
                        if callback:
                            callback(assessment, func_name, combined_args)
                        if on_block == "raise":
                            raise GuardBlockError(assessment, target=func_name, payload=combined_args)
                        elif on_block == "return":
                            return fallback if fallback is not None else assessment

                res = func(*args, **kwargs)

                if check_result:
                    res_assessment = check_tool_result(res)
                    if not res_assessment.allowed:
                        if callback:
                            callback(res_assessment, func_name, res)
                        if on_block == "raise":
                            raise GuardBlockError(res_assessment, target=f"{func_name}:result", payload=res)
                        elif on_block == "return":
                            return fallback if fallback is not None else res_assessment

                return res
            return sync_wrapper

    return decorator
