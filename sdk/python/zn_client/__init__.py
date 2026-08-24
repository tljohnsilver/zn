"""
zn-client: Official Python SDK for zn - Zero Trust Layer for AI Agents

Usage:
    from zn_client import ZnClient

    client = ZnClient(base_url="http://localhost:9090", api_key="your_key")
    result = client.check_tool_call("read_file", {"path": "/tmp/data.txt"})
"""

from .client import ZnClient, AsyncZnClient
from .models import ToolCallResult, AuditEntry, VaultStats
from .decorators import zn_guard
from .proxy import ZnMcpProxy

__version__ = "0.1.0"
__all__ = [
    "ZnClient",
    "AsyncZnClient",
    "ZnMcpProxy",
    "zn_guard",
    "ToolCallResult",
    "AuditEntry",
    "VaultStats",
]
