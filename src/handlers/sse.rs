//! Server-Sent Events (SSE) Handler
//!
//! Provides real-time streaming of audit events to connected clients.

use axum::{
    extract::State,
    response::sse::{Event, Sse},
    Extension,
};
use futures::stream::Stream;
use std::convert::Infallible;
use tokio::sync::broadcast;

use crate::audit::AuditEntry;
use crate::tenants::{TenantContext, TenantRole};

/// SSE handler state
#[derive(Clone)]
pub struct SseState {
    pub tx: broadcast::Sender<AuditEntry>,
}

/// SSE endpoint for real-time audit log streaming
pub async fn events(
    State(state): State<SseState>,
    Extension(tenant): Extension<TenantContext>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let mut rx = state.tx.subscribe();
    let tenant_namespace = tenant.namespace.clone();
    let is_super_admin = tenant.role == TenantRole::SuperAdmin;

    let stream = async_stream::stream! {
        loop {
            match rx.recv().await {
                Ok(entry) => {
                    // Filter by namespace unless SuperAdmin
                    if is_super_admin || entry.namespace.as_ref() == Some(&tenant_namespace) {
                        if let Ok(json) = serde_json::to_string(&entry) {
                            yield Ok(Event::default().data(json));
                        }
                    }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => {
                    // Skip lagged messages
                    continue;
                }
                Err(broadcast::error::RecvError::Closed) => {
                    break;
                }
            }
        }
    };

    Sse::new(stream).keep_alive(axum::response::sse::KeepAlive::default())
}
