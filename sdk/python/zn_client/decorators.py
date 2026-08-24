"""
Decorator for automatic zn security checks on tool calls.
"""

from __future__ import annotations

import functools
from typing import Any, Callable, Optional, TypeVar

from .client import ZnClient

F = TypeVar("F", bound=Callable[..., Any])


class ZnGuardError(Exception):
    """Raised when a tool call is blocked by zn policies."""
    
    def __init__(self, tool_name: str, policy: Optional[str] = None, reason: Optional[str] = None):
        self.tool_name = tool_name
        self.policy = policy
        self.reason = reason
        super().__init__(f"Tool '{tool_name}' blocked by policy: {policy or 'unknown'}")


def zn_guard(
    tools: Optional[list[str]] = None,
    client: Optional[ZnClient] = None,
    on_deny: Optional[Callable[[str, dict[str, Any]], Any]] = None,
    raise_on_deny: bool = True,
) -> Callable[[F], F]:
    """
    Decorator to automatically check tool calls against zn policies.
    
    Usage:
        @zn_guard(tools=["read_file", "write_file"])
        def my_tool_handler(tool_name: str, **kwargs):
            # Only executes if zn allows the call
            pass
    
    Args:
        tools: List of tool names to guard (if None, guards all)
        client: ZnClient instance (creates new one if not provided)
        on_deny: Optional callback when a tool call is denied
        raise_on_deny: Whether to raise ZnGuardError on denial (default True)
        
    Returns:
        Decorated function that checks zn policies before execution
    """
    
    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            # Extract tool_name from first arg or kwargs
            tool_name = args[0] if args else kwargs.get("tool_name", "unknown")
            
            # Skip check if not in guarded tools list
            if tools and tool_name not in tools:
                return func(*args, **kwargs)
            
            # Use provided client or create new one
            zn = client or ZnClient()
            
            try:
                # Build arguments from kwargs (excluding tool_name)
                arguments = {k: v for k, v in kwargs.items() if k != "tool_name"}
                
                # Check with zn
                result = zn.check_tool_call(tool_name, arguments)
                
                if not result.allowed:
                    if on_deny:
                        return on_deny(tool_name, arguments)
                    if raise_on_deny:
                        raise ZnGuardError(tool_name, result.policy, result.reason)
                    return None
                
                # Tool call is allowed, proceed
                return func(*args, **kwargs)
                
            finally:
                # Only close if we created the client
                if client is None:
                    zn.close()
        
        return wrapper  # type: ignore
    
    return decorator


class ZnContextManager:
    """
    Context manager for temporary zn guards.
    
    Usage:
        with ZnContextManager() as guard:
            guard.check("read_file", {"path": "/tmp/data"})
            # Do stuff if allowed
    """
    
    def __init__(
        self,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
    ):
        self._client = ZnClient(base_url=base_url, api_key=api_key)
    
    def check(self, tool_name: str, arguments: dict[str, Any]) -> bool:
        """Check if a tool call is allowed. Raises ZnGuardError if denied."""
        result = self._client.check_tool_call(tool_name, arguments)
        if not result.allowed:
            raise ZnGuardError(tool_name, result.policy, result.reason)
        return True
    
    def __enter__(self) -> ZnContextManager:
        return self
    
    def __exit__(self, *args: Any) -> None:
        self._client.close()
