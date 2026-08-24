//! REST API Handlers
//!
//! Contains all REST API endpoints for the zn Management API.

use axum::{
    extract::{Multipart, State},
    response::Json,
    Extension,
};
use serde_json::{json, Value};
use std::sync::Arc;

use crate::audit::AuditVault;
use crate::engine::ZnEngine;
use crate::tenants::{TenantContext, TenantRole, TenantStore};

/// Shared application state for handlers
#[derive(Clone)]
pub struct ApiState {
    pub vault: Arc<AuditVault>,
    pub engine: Arc<ZnEngine>,
    pub tenants: Arc<TenantStore>,
    pub consensus: Arc<crate::engine::consensus::ConsensusManager>,
}

// ============================================
// Health & Status
// ============================================

/// Health check endpoint
pub async fn health() -> &'static str {
    "OK"
}

/// Stats endpoint - returns audit statistics
pub async fn stats(
    State(state): State<ApiState>,
    Extension(tenant): Extension<TenantContext>,
) -> Json<Value> {
    let stats_result = if tenant.role == TenantRole::SuperAdmin {
        state.vault.stats()
    } else {
        state.vault.stats_by_namespace(&tenant.namespace)
    };

    match stats_result {
        Ok(stats) => Json(json!({
            "status": "ok",
            "stats": {
                "total": stats.total,
                "allowed": stats.allowed,
                "denied": stats.denied,
                "allow_rate": if stats.total > 0 {
                    (stats.allowed as f64 / stats.total as f64 * 100.0).round()
                } else {
                    100.0
                }
            }
        })),
        Err(e) => Json(json!({
            "status": "error",
            "error": e.to_string()
        })),
    }
}

// ============================================
// Audit Logs
// ============================================

/// Recent logs endpoint - returns last N audit entries
pub async fn logs(
    State(state): State<ApiState>,
    Extension(tenant): Extension<TenantContext>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Json<Value> {
    let limit: usize = params
        .get("limit")
        .and_then(|s| s.parse().ok())
        .unwrap_or(50)
        .min(500);

    let logs_result = if tenant.role == TenantRole::SuperAdmin {
        state.vault.get_recent(limit)
    } else {
        state
            .vault
            .get_recent_by_namespace(&tenant.namespace, limit)
    };

    match logs_result {
        Ok(entries) => Json(json!({
            "status": "ok",
            "count": entries.len(),
            "entries": entries
        })),
        Err(e) => Json(json!({
            "status": "error",
            "error": e.to_string()
        })),
    }
}

// ============================================
// Policy Management
// ============================================

/// List active policies endpoint
pub async fn policies_list(State(state): State<ApiState>) -> Json<Value> {
    let policies = state.engine.list_policies();
    Json(json!({
        "status": "ok",
        "count": policies.len(),
        "entries": policies
    }))
}

/// Upload new policy endpoint
pub async fn policies_upload(
    State(state): State<ApiState>,
    mut multipart: Multipart,
) -> Json<Value> {
    while let Some(field) = multipart.next_field().await.unwrap_or(None) {
        let name = field.name().unwrap_or("").to_string();
        if name == "policy" {
            let filename = field
                .file_name()
                .map(|s| s.to_string())
                .unwrap_or_else(|| format!("policy_{}.wasm", chrono::Utc::now().timestamp()));

            if let Ok(bytes) = field.bytes().await {
                // Save to policies directory
                let path = std::path::Path::new("policies").join(&filename);
                if let Err(e) = std::fs::write(&path, &bytes) {
                    return Json(json!({
                        "status": "error",
                        "error": format!("Failed to save policy: {}", e)
                    }));
                }

                // Register with engine
                if let Err(e) = state.engine.register_policy_from_file(&path) {
                    return Json(json!({
                        "status": "error",
                        "error": format!("Failed to load policy: {}", e)
                    }));
                }

                return Json(json!({
                    "status": "ok",
                    "message": format!("Policy '{}' uploaded and registered", filename)
                }));
            }
        }
    }

    Json(json!({
        "status": "error",
        "error": "No file uploaded"
    }))
}

#[derive(serde::Deserialize)]
pub struct DeletePolicyRequest {
    pub name: String,
}

/// Delete policy endpoint
pub async fn policies_delete(
    State(state): State<ApiState>,
    axum::Json(payload): axum::Json<DeletePolicyRequest>,
) -> Json<Value> {
    state.engine.unregister_policy(&payload.name);

    let path = std::path::Path::new("policies").join(format!("{}.wasm", payload.name));
    if path.exists() {
        if let Err(e) = std::fs::remove_file(path) {
            return Json(json!({
                "status": "error",
                "error": format!("Failed to delete policy file: {}", e)
            }));
        }
    }

    Json(json!({
        "status": "ok",
        "message": format!("Policy '{}' deleted", payload.name)
    }))
}

// ============================================
// Tenant Management
// ============================================

#[derive(serde::Deserialize)]
pub struct CreateTenantRequest {
    pub name: String,
    pub namespace: String,
    pub api_key: String,
}

/// Create a new tenant (SuperAdmin only)
pub async fn tenants_create(
    State(state): State<ApiState>,
    Extension(tenant): Extension<TenantContext>,
    axum::Json(payload): axum::Json<CreateTenantRequest>,
) -> Json<Value> {
    if tenant.role != TenantRole::SuperAdmin {
        return Json(json!({
            "status": "error",
            "error": "Forbidden: SuperAdmin role required"
        }));
    }

    match state
        .tenants
        .create_tenant(&payload.name, &payload.namespace, &payload.api_key)
    {
        Ok(_) => Json(json!({
            "status": "ok",
            "message": "Tenant created successfully"
        })),
        Err(e) => Json(json!({
            "status": "error",
            "error": e.to_string()
        })),
    }
}

/// List all tenants (SuperAdmin only)
pub async fn tenants_list(
    State(state): State<ApiState>,
    Extension(tenant): Extension<TenantContext>,
) -> Json<Value> {
    if tenant.role != TenantRole::SuperAdmin {
        return Json(json!({
            "status": "error",
            "error": "Forbidden: SuperAdmin role required"
        }));
    }

    match state.tenants.list_tenants() {
        Ok(tenants) => Json(json!({
            "status": "ok",
            "count": tenants.len(),
            "tenants": tenants
        })),
        Err(e) => Json(json!({
            "status": "error",
            "error": e.to_string()
        })),
    }
}
// ============================================
// Consensus Management (M-of-N)
// ============================================

/// List pending authorizations
pub async fn consensus_list(State(state): State<ApiState>) -> Json<Value> {
    let pending = state.consensus.list_pending();
    Json(json!({
        "status": "ok",
        "count": pending.len(),
        "entries": pending
    }))
}

#[derive(serde::Deserialize)]
pub struct SignRequest {
    pub action_id: String,
    pub witness_name: Option<String>,
}

/// Sign a pending action (as a Human)
pub async fn consensus_sign(
    State(state): State<ApiState>,
    Extension(tenant): Extension<TenantContext>,
    axum::Json(payload): axum::Json<SignRequest>,
) -> Json<Value> {
    use crate::engine::consensus::WitnessType;

    let witness = WitnessType::HumanAdmin(tenant.name);
    match state.consensus.sign_action(&payload.action_id, witness) {
        Ok(status) => Json(json!({
            "status": "ok",
            "action_status": status
        })),
        Err(e) => Json(json!({
            "status": "error",
            "error": e
        })),
    }
}

#[derive(serde::Deserialize)]
pub struct DenyRequest {
    pub action_id: String,
    pub reason: String,
}

/// Deny a pending action
pub async fn consensus_deny(
    State(state): State<ApiState>,
    axum::Json(payload): axum::Json<DenyRequest>,
) -> Json<Value> {
    match state
        .consensus
        .deny_action(&payload.action_id, &payload.reason)
    {
        Ok(_) => Json(json!({
            "status": "ok",
            "message": "Action denied"
        })),
        Err(e) => Json(json!({
            "status": "error",
            "error": e
        })),
    }
}
