"""
Main client classes for zn-client.
"""

from __future__ import annotations

import json
import os
from typing import Any, Generator, Optional

import httpx
import sseclient

from .models import AuditEntry, ToolCallResult, VaultStats, PolicyInfo


class ZnClient:
    """
    Synchronous client for the zn API.
    
    Usage:
        client = ZnClient(base_url="http://localhost:9090", api_key="your_key")
        result = client.check_tool_call("read_file", {"path": "/tmp/data.txt"})
    """
    
    def __init__(
        self,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        timeout: float = 30.0,
        verify_ssl: bool = True,
    ):
        """
        Initialize the zn client.
        
        Args:
            base_url: zn server URL (defaults to ZN_URL env var or localhost:9090)
            api_key: API key for authentication (defaults to ZN_API_KEY env var)
            timeout: Request timeout in seconds
            verify_ssl: Whether to verify SSL certificates
        """
        self.base_url = (base_url or os.environ.get("ZN_URL", "http://localhost:9090")).rstrip("/")
        self.api_key = api_key or os.environ.get("ZN_API_KEY")
        self.timeout = timeout
        self._client = httpx.Client(
            base_url=self.base_url,
            timeout=timeout,
            verify=verify_ssl,
            headers=self._build_headers(),
        )
    
    def _build_headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        return headers
    
    def check_tool_call(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        agent_id: Optional[str] = None,
    ) -> ToolCallResult:
        """
        Check if a tool call would be allowed by zn policies.
        
        Args:
            tool_name: Name of the tool to call
            arguments: Tool call arguments
            agent_id: Optional agent identifier
            
        Returns:
            ToolCallResult with allowed status and policy info
        """
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": arguments,
            },
        }
        if agent_id:
            payload["agent_id"] = agent_id
        
        response = self._client.post("/", json=payload)
        response.raise_for_status()
        data = response.json()
        
        if "error" in data:
            return ToolCallResult(
                allowed=False,
                policy=data["error"].get("data", {}).get("policy"),
                reason=data["error"].get("message"),
                request_id=str(data.get("id")),
            )
        
        return ToolCallResult(
            allowed=True,
            request_id=str(data.get("id")),
        )
    
    def get_stats(self) -> VaultStats:
        """Get audit vault statistics."""
        response = self._client.get("/stats")
        response.raise_for_status()
        data = response.json()
        return VaultStats(**data["stats"])
    
    def get_logs(self, limit: int = 50) -> list[AuditEntry]:
        """
        Get recent audit log entries.
        
        Args:
            limit: Maximum number of entries to return (max 500)
        """
        response = self._client.get("/logs", params={"limit": min(limit, 500)})
        response.raise_for_status()
        data = response.json()
        return [AuditEntry(**entry) for entry in data.get("entries", [])]
    
    def list_policies(self) -> list[PolicyInfo]:
        """List all active WASM policies."""
        response = self._client.get("/policies")
        response.raise_for_status()
        data = response.json()
        return [PolicyInfo(**p) for p in data.get("entries", [])]
    
    def stream_events(self) -> Generator[AuditEntry, None, None]:
        """
        Stream real-time audit events via SSE.
        
        Yields:
            AuditEntry objects as events occur
        """
        with self._client.stream("GET", "/events", headers={"Accept": "text/event-stream"}) as response:
            client = sseclient.SSEClient(response.iter_lines())
            for event in client.events():
                if event.data:
                    try:
                        data = json.loads(event.data)
                        yield AuditEntry(**data)
                    except (json.JSONDecodeError, ValueError):
                        continue
    
    def close(self) -> None:
        """Close the HTTP client."""
        self._client.close()
    
    def __enter__(self) -> ZnClient:
        return self
    
    def __exit__(self, *args: Any) -> None:
        self.close()


class AsyncZnClient:
    """
    Asynchronous client for the zn API.
    
    Usage:
        async with AsyncZnClient(base_url="http://localhost:9090") as client:
            result = await client.check_tool_call("read_file", {"path": "/tmp"})
    """
    
    def __init__(
        self,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        timeout: float = 30.0,
        verify_ssl: bool = True,
    ):
        self.base_url = (base_url or os.environ.get("ZN_URL", "http://localhost:9090")).rstrip("/")
        self.api_key = api_key or os.environ.get("ZN_API_KEY")
        self.timeout = timeout
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=timeout,
            verify=verify_ssl,
            headers=self._build_headers(),
        )
    
    def _build_headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        return headers
    
    async def check_tool_call(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        agent_id: Optional[str] = None,
    ) -> ToolCallResult:
        """Check if a tool call would be allowed by zn policies."""
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": arguments,
            },
        }
        if agent_id:
            payload["agent_id"] = agent_id
        
        response = await self._client.post("/", json=payload)
        response.raise_for_status()
        data = response.json()
        
        if "error" in data:
            return ToolCallResult(
                allowed=False,
                policy=data["error"].get("data", {}).get("policy"),
                reason=data["error"].get("message"),
            )
        
        return ToolCallResult(allowed=True)
    
    async def get_stats(self) -> VaultStats:
        """Get audit vault statistics."""
        response = await self._client.get("/stats")
        response.raise_for_status()
        data = response.json()
        return VaultStats(**data["stats"])
    
    async def get_logs(self, limit: int = 50) -> list[AuditEntry]:
        """Get recent audit log entries."""
        response = await self._client.get("/logs", params={"limit": min(limit, 500)})
        response.raise_for_status()
        data = response.json()
        return [AuditEntry(**entry) for entry in data.get("entries", [])]
    
    async def close(self) -> None:
        """Close the HTTP client."""
        await self._client.aclose()
    
    async def __aenter__(self) -> AsyncZnClient:
        return self
    
    async def __aexit__(self, *args: Any) -> None:
        await self.close()
