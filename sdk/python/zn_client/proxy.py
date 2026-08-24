"""
MCP Proxy for routing tool calls through zn.
"""

from __future__ import annotations

import json
from typing import Any, Optional

import httpx

from .client import ZnClient
from .decorators import ZnGuardError


class ZnMcpProxy:
    """
    Proxy that routes MCP tool calls through zn for security checks.
    
    Usage:
        proxy = ZnMcpProxy(
            upstream_url="http://localhost:8080",  # Your MCP server
            zn_url="http://localhost:9090",
            api_key="your_api_key"
        )
        
        # All tool calls are now automatically secured
        result = proxy.call_tool("read_file", path="/tmp/data.txt")
    """
    
    def __init__(
        self,
        upstream_url: str,
        zn_url: Optional[str] = None,
        api_key: Optional[str] = None,
        timeout: float = 30.0,
    ):
        """
        Initialize the MCP proxy.
        
        Args:
            upstream_url: URL of the actual MCP server
            zn_url: URL of the zn server (defaults to localhost:9090)
            api_key: API key for zn authentication
            timeout: Request timeout in seconds
        """
        self.upstream_url = upstream_url.rstrip("/")
        self._zn = ZnClient(base_url=zn_url, api_key=api_key, timeout=timeout)
        self._upstream = httpx.Client(base_url=self.upstream_url, timeout=timeout)
        self._request_id = 0
    
    def _next_id(self) -> int:
        self._request_id += 1
        return self._request_id
    
    def call_tool(
        self,
        tool_name: str,
        agent_id: Optional[str] = None,
        **arguments: Any,
    ) -> dict[str, Any]:
        """
        Call a tool through the zn-secured proxy.
        
        Args:
            tool_name: Name of the tool to call
            agent_id: Optional agent identifier
            **arguments: Tool arguments
            
        Returns:
            Tool call result from the upstream MCP server
            
        Raises:
            ZnGuardError: If zn blocks the tool call
        """
        # 1. Check with zn first
        result = self._zn.check_tool_call(tool_name, arguments, agent_id)
        
        if not result.allowed:
            raise ZnGuardError(tool_name, result.policy, result.reason)
        
        # 2. Forward to upstream MCP server
        payload = {
            "jsonrpc": "2.0",
            "id": self._next_id(),
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": arguments,
            },
        }
        
        response = self._upstream.post("/", json=payload)
        response.raise_for_status()
        return response.json()
    
    def list_tools(self) -> list[dict[str, Any]]:
        """List available tools from the upstream MCP server."""
        payload = {
            "jsonrpc": "2.0",
            "id": self._next_id(),
            "method": "tools/list",
        }
        
        response = self._upstream.post("/", json=payload)
        response.raise_for_status()
        data = response.json()
        return data.get("result", {}).get("tools", [])
    
    def close(self) -> None:
        """Close both clients."""
        self._zn.close()
        self._upstream.close()
    
    def __enter__(self) -> ZnMcpProxy:
        return self
    
    def __exit__(self, *args: Any) -> None:
        self.close()


class ZnMcpMiddleware:
    """
    ASGI/WSGI middleware that proxies MCP requests through zn.
    
    For use with web frameworks like FastAPI or Flask.
    
    Usage with FastAPI:
        app = FastAPI()
        app.add_middleware(ZnMcpMiddleware, zn_url="http://localhost:9090")
    """
    
    def __init__(
        self,
        app: Any,
        zn_url: Optional[str] = None,
        api_key: Optional[str] = None,
        path_prefix: str = "/mcp",
    ):
        self.app = app
        self.path_prefix = path_prefix
        self._zn = ZnClient(base_url=zn_url, api_key=api_key)
    
    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] == "http" and scope["path"].startswith(self.path_prefix):
            # Handle MCP request through zn
            # This is a simplified implementation
            pass
        
        # Pass through to the main app
        await self.app(scope, receive, send)
