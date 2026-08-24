//! Authentication module for zn Management API
//!
//! Provides multi-modal authentication:
//! 1. API Key (X-API-Key or Bearer) - looked up in TenantStore
//! 2. JWT (Signed by trusted secret or OIDC)
//! 3. Legacy single API key (super-admin fallback)

use crate::tenants::{TenantContext, TenantRole, TenantStore};
use axum::{
    extract::Request,
    http::{header, StatusCode},
    middleware::Next,
    response::Response,
};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Authentication state shared across handlers
#[derive(Clone)]
pub struct AuthConfig {
    /// Legacy API key for super-admin (backwards compatibility)
    pub api_key: Option<String>,
    /// Secret for JWT validation (None = JWT disabled)
    pub jwt_secret: Option<String>,
    /// Tenant store for multi-tenancy
    pub tenant_store: Option<Arc<TenantStore>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
    pub iat: Option<usize>,
    pub roles: Option<Vec<String>>,
}

impl AuthConfig {
    pub fn new(api_key: Option<String>, jwt_secret: Option<String>) -> Self {
        Self {
            api_key,
            jwt_secret,
            tenant_store: None,
        }
    }

    pub fn with_tenant_store(mut self, store: Arc<TenantStore>) -> Self {
        self.tenant_store = Some(store);
        self
    }

    /// Check if authentication is required
    pub fn is_auth_required(&self) -> bool {
        self.api_key.is_some() || self.jwt_secret.is_some() || self.tenant_store.is_some()
    }
}

/// Super-admin context for legacy API key
pub fn super_admin_context() -> TenantContext {
    TenantContext {
        id: "super-admin".to_string(),
        name: "Super Admin".to_string(),
        namespace: "global".to_string(),
        role: TenantRole::SuperAdmin,
    }
}

/// Authentication middleware supporting API Keys, JWTs, and Multi-Tenancy
pub async fn api_key_auth(mut request: Request, next: Next) -> Result<Response, StatusCode> {
    // Get auth config from request extensions
    let auth_config = request.extensions().get::<Arc<AuthConfig>>().cloned();

    let config = match auth_config {
        Some(c) => c,
        None => return Ok(next.run(request).await),
    };

    // If no auth is configured, allow all
    if !config.is_auth_required() {
        return Ok(next.run(request).await);
    }

    // Extract authorization token
    let auth_header = request
        .headers()
        .get("X-API-Key")
        .or_else(|| request.headers().get(header::AUTHORIZATION))
        .and_then(|v| v.to_str().ok());

    let token = if let Some(header_val) = auth_header {
        Some(header_val.trim_start_matches("Bearer ").trim().to_string())
    } else {
        // Fallback: Check query parameters (for SSE/WebSocket)
        request.uri().query().and_then(|query| {
            query.split('&').find_map(|pair| {
                let (key, val) = pair.split_once('=')?;
                if key == "api_key" || key == "token" {
                    Some(val.to_string())
                } else {
                    None
                }
            })
        })
    };

    match token {
        Some(token) => {
            // 1. Check against Legacy Super-Admin API Key
            if let Some(expected_key) = &config.api_key {
                if constant_time_compare(&token, expected_key) {
                    // Inject super-admin context
                    request.extensions_mut().insert(super_admin_context());
                    return Ok(next.run(request).await);
                }
            }

            // 2. Check against Tenant Store (Multi-Tenancy)
            if let Some(store) = &config.tenant_store {
                if let Ok(Some(tenant_ctx)) = store.find_by_api_key(&token) {
                    if tenant_ctx.role == TenantRole::Blocked {
                        tracing::warn!("Blocked tenant attempted access: {}", tenant_ctx.name);
                        return Err(StatusCode::FORBIDDEN);
                    }
                    // Inject tenant context into request
                    request.extensions_mut().insert(tenant_ctx);
                    return Ok(next.run(request).await);
                }
            }

            // 3. Try JWT Validation
            if let Some(secret) = &config.jwt_secret {
                let decoding_key = DecodingKey::from_secret(secret.as_bytes());
                let validation = Validation::new(Algorithm::HS256);

                if let Ok(_token_data) = decode::<Claims>(&token, &decoding_key, &validation) {
                    // Valid JWT - treat as admin for now
                    request.extensions_mut().insert(super_admin_context());
                    return Ok(next.run(request).await);
                }
            }

            tracing::warn!("Failed authentication attempt with token provided");
            Err(StatusCode::UNAUTHORIZED)
        }
        None => {
            tracing::warn!("No authentication provided for protected resource");
            Err(StatusCode::UNAUTHORIZED)
        }
    }
}

/// Constant-time string comparison to prevent timing attacks
fn constant_time_compare(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in a.bytes().zip(b.bytes()) {
        result |= x ^ y;
    }
    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_compare() {
        assert!(constant_time_compare("test", "test"));
        assert!(!constant_time_compare("test", "Test"));
    }
}
