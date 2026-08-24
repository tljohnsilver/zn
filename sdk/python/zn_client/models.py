"""
Pydantic models for zn-client.
"""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field


class ToolCallResult(BaseModel):
    """Result of checking a tool call against zn policies."""
    
    allowed: bool = Field(..., description="Whether the tool call is allowed")
    policy: Optional[str] = Field(None, description="Policy that blocked the call (if denied)")
    reason: Optional[str] = Field(None, description="Reason for the decision")
    request_id: Optional[str] = Field(None, description="Unique request identifier")


class AuditEntry(BaseModel):
    """A single audit log entry."""
    
    id: str = Field(..., description="Unique event identifier")
    timestamp: datetime = Field(..., description="Event timestamp")
    event: str = Field(..., description="Event type (e.g., TOOL_CALL, POLICY_DENY)")
    tool_name: str = Field(..., description="Name of the tool involved")
    status: str = Field(..., description="Operation status (ALLOWED, DENIED)")
    policy_match: Optional[str] = Field(None, description="Policy that matched")
    payload: Optional[str] = Field(None, description="Scrubbed JSON-RPC payload")
    agent_id: Optional[str] = Field(None, description="Agent identifier")
    namespace: Optional[str] = Field(None, description="Tenant namespace")


class VaultStats(BaseModel):
    """Audit vault statistics."""
    
    total: int = Field(..., description="Total number of events")
    allowed: int = Field(..., description="Number of allowed events")
    denied: int = Field(..., description="Number of denied events")
    allow_rate: float = Field(..., description="Percentage of allowed events")


class PolicyInfo(BaseModel):
    """Information about a loaded WASM policy."""
    
    name: str = Field(..., description="Policy name")
    hash: Optional[str] = Field(None, description="SHA-256 hash of the policy")
    loaded_at: Optional[datetime] = Field(None, description="When the policy was loaded")


class TenantInfo(BaseModel):
    """Information about a tenant."""
    
    id: str = Field(..., description="Tenant ID")
    name: str = Field(..., description="Tenant name")
    namespace: str = Field(..., description="Tenant namespace")
    role: str = Field(..., description="Tenant role")
    created_at: datetime = Field(..., description="Creation timestamp")
