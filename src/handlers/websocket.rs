//! WebSocket Handler for MCP Protocol
//!
//! Handles bidirectional WebSocket connections for MCP tool calls.

use axum::{
    extract::{ws::WebSocketUpgrade, State},
    response::IntoResponse,
    Extension,
};
use futures::{SinkExt, StreamExt};
use std::sync::Arc;
use tokio::sync::broadcast;

use crate::audit::{AuditEntry, AuditVault};
use crate::config::ZnConfig;
use crate::engine::reputation::ReputationSystem;
use crate::engine::ZnEngine;
use crate::proxy::McpPool;
use crate::shield;
use crate::tenants::TenantContext;
use crate::webhooks;

/// WebSocket handler state
#[derive(Clone)]
pub struct WsState {
    pub tx: broadcast::Sender<AuditEntry>,
    pub vault: Arc<AuditVault>,
    pub reputation: Arc<ReputationSystem>,
    pub engine: Arc<ZnEngine>,
    pub pool: Arc<McpPool>,
    pub config: Arc<ZnConfig>,
    pub webhook_tx: tokio::sync::mpsc::Sender<webhooks::AlertPayload>,
}

/// MCP WebSocket handler with security checks
pub async fn mcp_handler(
    State(state): State<WsState>,
    ws: WebSocketUpgrade,
    Extension(tenant): Extension<TenantContext>,
    header_map: axum::http::HeaderMap,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    // 1. WebSocket Origin Guard
    let origin = header_map
        .get("origin")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    if !shield::McpShield::validate_origin(origin, &state.config.security.allowed_origins) {
        tracing::warn!("Blocked Unauthorized WebSocket Origin: {}", origin);
        return (axum::http::StatusCode::FORBIDDEN, "Origin not allowed").into_response();
    }

    // 2. Token-Based Auth (Optional additional check)
    let provided_token = params.get("token").cloned().or_else(|| {
        header_map
            .get("x-mcp-token")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string())
    });

    if let Some(required_token) = &state.config.security.mcp_ws_token {
        if provided_token.as_ref() != Some(required_token) {
            tracing::warn!("Blocked Unauthorized WebSocket Connection: Invalid or missing token");
            return (
                axum::http::StatusCode::UNAUTHORIZED,
                "Invalid security token",
            )
                .into_response();
        }
    }

    let namespace = tenant.namespace.clone();
    ws.on_upgrade(move |socket| handle_socket(socket, state, namespace))
}

/// Handle individual WebSocket connection
async fn handle_socket(socket: axum::extract::ws::WebSocket, _state: WsState, _namespace: String) {
    use axum::extract::ws::Message;

    let (mut sender, mut receiver) = socket.split();

    while let Some(Ok(msg)) = receiver.next().await {
        if let Message::Text(text) = msg {
            // For now, echo back - full MCP processing would go here
            // In production, this calls process_mcp_message from main.rs
            let response = format!(
                r#"{{"jsonrpc":"2.0","id":null,"result":{{"echo":"{}"}}}}"#,
                text.chars().take(50).collect::<String>()
            );

            if let Err(e) = sender.send(Message::Text(response)).await {
                tracing::error!("WS send error: {}", e);
                break;
            }
        }
    }
}
