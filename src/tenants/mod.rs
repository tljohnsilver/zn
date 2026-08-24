//! Tenant Management Module
//!
//! Provides multi-tenancy support for zn with:
//! - Per-tenant API keys
//! - Role-based access control
//! - Isolated audit logs via namespaces

use anyhow::{anyhow, Result};
use chrono::Utc;
use rusqlite::{params, Connection, Row};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

/// Tenant roles for access control
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TenantRole {
    SuperAdmin, // Full platform access
    Admin,      // Tenant management access
    User,       // Normal tenant access
    Viewer,     // Read-only tenant access
    Blocked,    // Access denied
}

impl TenantRole {
    pub fn parse(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "superadmin" => TenantRole::SuperAdmin,
            "admin" => TenantRole::Admin,
            "user" => TenantRole::User,
            "viewer" => TenantRole::Viewer,
            "blocked" => TenantRole::Blocked,
            _ => TenantRole::User,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            TenantRole::SuperAdmin => "superadmin",
            TenantRole::Admin => "admin",
            TenantRole::User => "user",
            TenantRole::Viewer => "viewer",
            TenantRole::Blocked => "blocked",
        }
    }
}

/// Represents a tenant (organization/user) in the system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tenant {
    pub id: String,
    pub name: String,
    pub namespace: String,
    pub api_key: String,
    pub role: TenantRole,
    pub created_at: String,
}

/// Context injected into requests after authentication
#[derive(Debug, Clone)]
pub struct TenantContext {
    pub id: String,
    pub name: String,
    pub namespace: String,
    pub role: TenantRole,
}

impl TenantContext {
    pub fn is_super_admin(&self) -> bool {
        self.role == TenantRole::SuperAdmin
    }

    pub fn is_admin(&self) -> bool {
        self.role == TenantRole::Admin || self.role == TenantRole::SuperAdmin
    }
}

/// Persistent storage for tenant data
pub struct TenantStore {
    conn: Arc<Mutex<Connection>>,
}

impl TenantStore {
    /// Create a new TenantStore, initializing the schema if needed
    pub fn new(conn: Arc<Mutex<Connection>>) -> Result<Self> {
        {
            let db = conn.lock().map_err(|e| anyhow!("Lock poisoned: {}", e))?;

            db.execute(
                "CREATE TABLE IF NOT EXISTS tenants (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL UNIQUE,
                    namespace TEXT NOT NULL UNIQUE,
                    api_key_hash TEXT NOT NULL UNIQUE,
                    role TEXT NOT NULL DEFAULT 'viewer',
                    created_at TEXT NOT NULL
                )",
                [],
            )
            .map_err(|e| anyhow!("Failed to create tenants table: {}", e))?;

            // Seed a default 'global' tenant if none exist for easy startup
            let count: i64 = db.query_row("SELECT COUNT(*) FROM tenants", [], |r| r.get(0))?;
            if count == 0 {
                let id = Uuid::new_v4().to_string();

                // 1. Try to get API key from environment variable
                // 2. Fallback to generating a high-entropy random key
                let (api_key, source) = if let Ok(env_key) = std::env::var("ZN_API_KEY") {
                    (env_key, "Environment Variable (ZN_API_KEY)")
                } else {
                    use rand::distributions::{Alphanumeric, DistString};
                    let random_key = Alphanumeric.sample_string(&mut rand::thread_rng(), 32);
                    (random_key, "Generated Random Key")
                };

                let hash = Self::hash_api_key(&api_key);
                let created_at = Utc::now().to_rfc3339();

                db.execute(
                    "INSERT INTO tenants (id, name, namespace, api_key_hash, role, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![id, "Default Org", "global", hash, "superadmin", created_at],
                )?;

                // Print the key and security warning
                println!("\n\x1b[32;1m🛡️ zn Initialized Successfully!\x1b[0m");
                println!("\x1b[33mNo superadmin tenant found. A new one has been seeded.\x1b[0m");
                println!("Source: {}", source);
                println!("\x1b[32;1mSuperAdmin API Key: {}\x1b[0m", api_key);
                println!(
                    "\x1b[31;1mIMPORTANT: Save this key! It will not be shown again.\x1b[0m\n"
                );

                tracing::info!("Seeded default SuperAdmin tenant from {}", source);
            }

            tracing::info!("TenantStore initialized");
        }

        Ok(Self { conn })
    }

    /// Create a new tenant (used by main.rs)
    pub fn create_tenant(&self, name: &str, namespace: &str, api_key: &str) -> Result<()> {
        let db = self
            .conn
            .lock()
            .map_err(|e| anyhow!("Lock poisoned: {}", e))?;

        let id = Uuid::new_v4().to_string();
        let api_key_hash = Self::hash_api_key(api_key);
        let created_at = Utc::now().to_rfc3339();

        db.execute(
            "INSERT INTO tenants (id, name, namespace, api_key_hash, role, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![id, name, namespace, api_key_hash, "user", created_at],
        ).map_err(|e| anyhow!("Failed to create tenant: {}", e))?;

        Ok(())
    }

    /// List all tenants (used by main.rs)
    pub fn list_tenants(&self) -> Result<Vec<Tenant>> {
        let db = self
            .conn
            .lock()
            .map_err(|e| anyhow!("Lock poisoned: {}", e))?;

        let mut stmt = db.prepare(
            "SELECT id, name, namespace, role, created_at FROM tenants ORDER BY created_at DESC",
        )?;

        let tenants = stmt.query_map([], |row: &Row| {
            let role_str: String = row.get(3)?;
            Ok(Tenant {
                id: row.get(0)?,
                name: row.get(1)?,
                namespace: row.get(2)?,
                api_key: "[REDACTED]".to_string(),
                role: TenantRole::parse(&role_str),
                created_at: row.get(4)?,
            })
        })?;

        let mut result = Vec::new();
        for tenant in tenants {
            result.push(tenant?);
        }
        Ok(result)
    }

    /// Look up a tenant by API key (for authentication)
    pub fn find_by_api_key(&self, api_key: &str) -> Result<Option<TenantContext>> {
        let db = self
            .conn
            .lock()
            .map_err(|e| anyhow!("Lock poisoned: {}", e))?;
        let api_key_hash = Self::hash_api_key(api_key);

        let mut stmt =
            db.prepare("SELECT id, name, namespace, role FROM tenants WHERE api_key_hash = ?1")?;

        let result = stmt.query_row([api_key_hash], |row: &Row| {
            let role_str: String = row.get(3)?;
            Ok(TenantContext {
                id: row.get(0)?,
                name: row.get(1)?,
                namespace: row.get(2)?,
                role: TenantRole::parse(&role_str),
            })
        });

        match result {
            Ok(ctx) => Ok(Some(ctx)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(anyhow!("Database error: {}", e)),
        }
    }

    /// Simple SHA-256 hash for API key storage
    fn hash_api_key(key: &str) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(key.as_bytes());
        hex::encode(hasher.finalize())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn setup_test_store() -> TenantStore {
        // Use in-memory database for tests
        let conn = Connection::open_in_memory().expect("Failed to open in-memory DB");
        let conn = Arc::new(Mutex::new(conn));
        // Set env var to avoid random key generation logs
        std::env::set_var("ZN_API_KEY", "test_super_admin_key");
        TenantStore::new(conn).expect("Failed to create TenantStore")
    }

    #[test]
    fn test_role_from_str() {
        assert_eq!(TenantRole::parse("superadmin"), TenantRole::SuperAdmin);
        assert_eq!(TenantRole::parse("SUPERADMIN"), TenantRole::SuperAdmin);
        assert_eq!(TenantRole::parse("admin"), TenantRole::Admin);
        assert_eq!(TenantRole::parse("user"), TenantRole::User);
        assert_eq!(TenantRole::parse("viewer"), TenantRole::Viewer);
        assert_eq!(TenantRole::parse("blocked"), TenantRole::Blocked);
        assert_eq!(TenantRole::parse("unknown"), TenantRole::User); // Default
    }

    #[test]
    fn test_role_as_str() {
        assert_eq!(TenantRole::SuperAdmin.as_str(), "superadmin");
        assert_eq!(TenantRole::Admin.as_str(), "admin");
        assert_eq!(TenantRole::User.as_str(), "user");
        assert_eq!(TenantRole::Viewer.as_str(), "viewer");
        assert_eq!(TenantRole::Blocked.as_str(), "blocked");
    }

    #[test]
    fn test_tenant_context_permissions() {
        let super_admin = TenantContext {
            id: "1".to_string(),
            name: "Super".to_string(),
            namespace: "global".to_string(),
            role: TenantRole::SuperAdmin,
        };

        let admin = TenantContext {
            id: "2".to_string(),
            name: "Admin".to_string(),
            namespace: "org_a".to_string(),
            role: TenantRole::Admin,
        };

        let user = TenantContext {
            id: "3".to_string(),
            name: "User".to_string(),
            namespace: "org_a".to_string(),
            role: TenantRole::User,
        };

        assert!(super_admin.is_super_admin());
        assert!(super_admin.is_admin());

        assert!(!admin.is_super_admin());
        assert!(admin.is_admin());

        assert!(!user.is_super_admin());
        assert!(!user.is_admin());
    }

    #[test]
    fn test_create_and_list_tenant() {
        let store = setup_test_store();

        // Create a new tenant
        store
            .create_tenant("Acme Corp", "acme", "acme_api_key_123")
            .unwrap();

        // List tenants (should include default + acme)
        let tenants = store.list_tenants().unwrap();
        assert!(tenants.len() >= 2);

        let acme = tenants.iter().find(|t| t.name == "Acme Corp");
        assert!(acme.is_some());
        assert_eq!(acme.unwrap().namespace, "acme");
        assert_eq!(acme.unwrap().api_key, "[REDACTED]"); // API key should be redacted
    }

    #[test]
    fn test_find_by_api_key() {
        let store = setup_test_store();

        // Find super admin by env key
        let found = store.find_by_api_key("test_super_admin_key").unwrap();
        assert!(found.is_some());
        let ctx = found.unwrap();
        assert_eq!(ctx.role, TenantRole::SuperAdmin);
        assert_eq!(ctx.namespace, "global");

        // Create and find a new tenant
        store
            .create_tenant("Test Org", "test_ns", "test_key_abc")
            .unwrap();
        let found = store.find_by_api_key("test_key_abc").unwrap();
        assert!(found.is_some());
        let ctx = found.unwrap();
        assert_eq!(ctx.namespace, "test_ns");
        assert_eq!(ctx.role, TenantRole::User);

        // Invalid key should return None
        let not_found = store.find_by_api_key("wrong_key").unwrap();
        assert!(not_found.is_none());
    }

    #[test]
    fn test_api_key_hashing() {
        let hash1 = TenantStore::hash_api_key("my_secret_key");
        let hash2 = TenantStore::hash_api_key("my_secret_key");
        let hash3 = TenantStore::hash_api_key("different_key");

        assert_eq!(hash1, hash2); // Same key = same hash
        assert_ne!(hash1, hash3); // Different key = different hash
        assert_eq!(hash1.len(), 64); // SHA-256 = 64 hex chars
    }
}
