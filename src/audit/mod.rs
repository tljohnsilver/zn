//! Audit Vault Module
//!
//! Provides persistent storage for security audit logs using SQLite.
//!
//! ## Features
//! - Thread-safe database access via Arc<Mutex<Connection>>
//! - Automatic table creation on initialization
//! - Efficient query for recent entries

pub mod exporter;

use crate::metrics;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, Result};
use chrono::Utc;
use rusqlite::{params, Connection, Row};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use tracing::{debug, error, info};
use uuid::Uuid;

/// Represents a single audit event in the system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Unique event identifier
    pub id: String,
    /// ISO 8601 timestamp
    pub timestamp: String,
    /// Event type (e.g., TOOL_CALL, POLICY_DENY)
    pub event: String,
    /// Name of the tool involved
    pub tool_name: String,
    /// Operation status (ALLOWED, DENIED)
    pub status: String,
    /// Name of the policy that matched
    pub policy_match: Option<String>,
    /// Scrubbed JSON-RPC payload
    pub payload: Option<String>,
    /// ID of the agent that made the request
    pub agent_id: Option<String>,
    /// Multi-tenant namespace
    pub namespace: Option<String>,
    /// Neural anomaly score (0.0 to 1.0 or higher)
    pub anomaly_score: Option<f32>,
    /// Nearest neighbor entry for audit (format: "text:distance")
    pub nearest_neighbor: Option<String>,
    /// B-3 Fusion Gate evidence; present only when the neural camera
    /// participated in a block decision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fusion: Option<FusionEvidence>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VaultStats {
    pub total: usize,
    pub allowed: usize,
    pub denied: usize,
}

impl AuditEntry {
    /// Create a new audit entry with the current timestamp
    pub fn new(
        event: impl Into<String>,
        tool_name: impl Into<String>,
        status: impl Into<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now().to_rfc3339(),
            event: event.into(),
            tool_name: tool_name.into(),
            status: status.into(),
            policy_match: None,
            payload: None,
            agent_id: None,
            namespace: None,
            anomaly_score: None,
            nearest_neighbor: None,
            fusion: None,
        }
    }

    pub fn with_policy(mut self, policy: impl Into<String>) -> Self {
        self.policy_match = Some(policy.into());
        self
    }

    pub fn with_payload(mut self, payload: impl Into<String>) -> Self {
        self.payload = Some(payload.into());
        self
    }

    pub fn with_agent_id(mut self, agent_id: impl Into<String>) -> Self {
        self.agent_id = Some(agent_id.into());
        self
    }

    pub fn with_nearest_neighbor(mut self, nn: impl Into<String>) -> Self {
        self.nearest_neighbor = Some(nn.into());
        self
    }

    /// B-3: attach Fusion Gate evidence (block events, fusion active only).
    pub fn with_fusion(mut self, fusion: FusionEvidence) -> Self {
        self.fusion = Some(fusion);
        self
    }
}

/// B-3 Fusion Gate evidence: which cameras fired plus the neural inputs that
/// produced the decision. Attached to audit entries only when the neural
/// camera actively participated AND the call was blocked.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FusionEvidence {
    /// Cameras that fired, e.g. ["rules", "neural"].
    pub cameras: Vec<String>,
    /// Head probability in [0, 1] at decision time.
    pub neural_score: f32,
    /// Threshold applied to `neural_score`.
    pub tau: f32,
    /// Model version id (must match the exported score fixture).
    pub model_id: String,
}

/// Persistent storage for audit logs with built-in encryption support
pub struct AuditVault {
    conn: Arc<Mutex<Connection>>,
    #[allow(dead_code)]
    db_path: String,
    /// Key for payload encryption (AES-256-GCM)
    encryption_key: Option<[u8; 32]>,
}

impl AuditVault {
    /// Create a new AuditVault, initializing the database schema if needed
    pub fn new(db_path: &str, encryption_key: Option<&str>) -> Result<Self> {
        info!("Initializing AuditVault at: {}", db_path);

        let conn = Connection::open(db_path)
            .map_err(|e| anyhow!("Failed to open audit database '{}': {}", db_path, e))?;

        // Create metadata table for persistent configuration (like salt)
        conn.execute(
            "CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )",
            [],
        )
        .map_err(|e| anyhow!("Failed to create metadata table: {}", e))?;

        // Derive key if provided
        let derived_key = if let Some(key_str) = encryption_key {
            // Get or create random salt
            let mut stmt =
                conn.prepare("SELECT value FROM metadata WHERE key = 'derivation_salt'")?;
            let salt_hex: Option<String> = stmt.query_row([], |row| row.get(0)).ok();

            let salt = if let Some(hex_str) = salt_hex {
                hex::decode(hex_str).map_err(|e| anyhow!("Failed to decode salt: {}", e))?
            } else {
                use rand::RngCore;
                let mut new_salt = [0u8; 16];
                rand::thread_rng().fill_bytes(&mut new_salt);
                let hex_str = hex::encode(new_salt);
                conn.execute(
                    "INSERT INTO metadata (key, value) VALUES ('derivation_salt', ?1)",
                    [hex_str],
                )?;
                new_salt.to_vec()
            };

            let mut key = [0u8; 32];
            argon2::Argon2::default()
                .hash_password_into(key_str.as_bytes(), &salt, &mut key)
                .map_err(|e| anyhow!("Failed to derive encryption key: {}", e))?;
            info!("Audit encryption enabled with persistent salt");
            Some(key)
        } else {
            None
        };

        // Create table with index for efficient timestamp queries
        conn.execute(
            "CREATE TABLE IF NOT EXISTS audit_logs (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                event TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                status TEXT NOT NULL,
                policy_match TEXT,
                payload TEXT,
                agent_id TEXT,
                namespace TEXT,
                anomaly_score REAL,
                nearest_neighbor TEXT,
                fusion TEXT
            )",
            [],
        )
        .map_err(|e| anyhow!("Failed to create audit_logs table: {}", e))?;

        // Migration: add nearest_neighbor column if missing (E-2)
        // Check if column exists first
        let has_column: bool = conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('audit_logs') WHERE name = 'nearest_neighbor'",
                [],
                |r| r.get::<_, i64>(0),
            )
            .map(|c| c > 0)
            .unwrap_or(false);
        if !has_column {
            info!("Adding nearest_neighbor column via migration");
            conn.execute(
                "ALTER TABLE audit_logs ADD COLUMN nearest_neighbor TEXT",
                [],
            )
            .ok();
        }

        // Migration: add fusion column if missing (B-3)
        let has_fusion: bool = conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('audit_logs') WHERE name = 'fusion'",
                [],
                |r| r.get::<_, i64>(0),
            )
            .map(|c| c > 0)
            .unwrap_or(false);
        if !has_fusion {
            info!("Adding fusion evidence column via migration");
            conn.execute("ALTER TABLE audit_logs ADD COLUMN fusion TEXT", [])
                .ok();
        }

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            db_path: db_path.to_string(),
            encryption_key: derived_key,
        })
    }

    /// Store a new audit entry in the database
    pub fn log(&self, entry: AuditEntry) -> Result<()> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| anyhow!("Lock poisoned: {}", e))?;

        // Encrypt payload if key is available
        let payload = if let (Some(key_bytes), Some(p_raw)) = (&self.encryption_key, &entry.payload)
        {
            let cipher = Aes256Gcm::new(key_bytes.into());
            let nonce_bytes = Uuid::new_v4().as_bytes()[..12].to_vec();
            let nonce = Nonce::from_slice(&nonce_bytes);

            let encrypted = cipher
                .encrypt(nonce, p_raw.as_bytes())
                .map_err(|_| anyhow!("Payload encryption failed"))?;

            use base64::{engine::general_purpose, Engine as _};
            let encoded = format!(
                "{}:{}",
                general_purpose::STANDARD.encode(&nonce_bytes),
                general_purpose::STANDARD.encode(&encrypted)
            );
            Some(encoded)
        } else {
            entry.payload.clone()
        };

        let nearest_neighbor = entry.nearest_neighbor.clone();
        let fusion = entry
            .fusion
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|e| anyhow!("Fusion evidence serialization failed: {}", e))?;
        conn.execute(
            "INSERT INTO audit_logs (id, timestamp, event, tool_name, status, policy_match, payload, agent_id, namespace, anomaly_score, nearest_neighbor, fusion)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                entry.id,
                entry.timestamp,
                entry.event,
                entry.tool_name,
                entry.status,
                entry.policy_match,
                payload,
                entry.agent_id,
                entry.namespace,
                entry.anomaly_score,
                nearest_neighbor,
                fusion,
            ],
        ).map_err(|e| {
            error!("Failed to log audit entry: {}", e);
            anyhow!("Database error: {}", e)
        })?;

        debug!("Audited event: {} by tool {}", entry.event, entry.tool_name);
        metrics::record_audit_entry();
        Ok(())
    }

    /// Retrieve recent audit logs from the database
    pub fn get_recent(&self, limit: usize) -> Result<Vec<AuditEntry>> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| anyhow!("Lock poisoned: {}", e))?;

        let mut stmt = conn.prepare(
            "SELECT id, timestamp, event, tool_name, status, policy_match, payload, agent_id, namespace, anomaly_score, nearest_neighbor, fusion
             FROM audit_logs ORDER BY timestamp DESC LIMIT ?"
        ).map_err(|e| anyhow!("Failed to prepare query: {}", e))?;

        let entries = stmt
            .query_map([limit], |row: &Row| {
                let id: String = row.get(0)?;
                let timestamp: String = row.get(1)?;
                let event: String = row.get(2)?;
                let tool_name: String = row.get(3)?;
                let status: String = row.get(4)?;
                let policy_match: Option<String> = row.get(5)?;
                let mut payload: Option<String> = row.get(6)?;
                let agent_id: Option<String> = row.get(7)?;
                let namespace: Option<String> = row.get(8)?;
                let anomaly_score: Option<f32> = row.get(9)?;
                let nearest_neighbor: Option<String> = row.get(10)?;
                let fusion: Option<String> = row.get(11)?;
                let fusion: Option<FusionEvidence> =
                    fusion.and_then(|s| serde_json::from_str(&s).ok());

                // Decrypt payload if key is available
                if let (Some(key_bytes), Some(p_enc)) = (&self.encryption_key, &payload) {
                    if p_enc.contains(':') {
                        let parts: Vec<&str> = p_enc.split(':').collect();
                        if parts.len() == 2 {
                            use base64::{engine::general_purpose, Engine as _};
                            if let (Ok(nonce_bytes), Ok(ciphertext)) = (
                                general_purpose::STANDARD.decode(parts[0]),
                                general_purpose::STANDARD.decode(parts[1]),
                            ) {
                                let cipher = Aes256Gcm::new(key_bytes.into());
                                let nonce = Nonce::from_slice(&nonce_bytes);
                                if let Ok(decrypted) = cipher.decrypt(nonce, ciphertext.as_slice())
                                {
                                    if let Ok(s) = String::from_utf8(decrypted) {
                                        payload = Some(s);
                                    }
                                }
                            }
                        }
                    }
                }

                Ok(AuditEntry {
                    id,
                    timestamp,
                    event,
                    tool_name,
                    status,
                    policy_match,
                    payload,
                    agent_id,
                    namespace,
                    anomaly_score,
                    nearest_neighbor,
                    fusion,
                })
            })
            .map_err(|e| anyhow!("Failed to execute query: {}", e))?;

        let mut result = Vec::new();
        for entry in entries {
            result.push(entry?);
        }

        Ok(result)
    }

    pub fn stats(&self) -> Result<VaultStats> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| anyhow!("Lock poisoned: {}", e))?;
        let total: usize =
            conn.query_row("SELECT COUNT(*) FROM audit_logs", [], |r: &Row| r.get(0))?;
        let allowed: usize = conn.query_row(
            "SELECT COUNT(*) FROM audit_logs WHERE status = 'ALLOWED'",
            [],
            |r: &Row| r.get(0),
        )?;
        let denied: usize = conn.query_row(
            "SELECT COUNT(*) FROM audit_logs WHERE status = 'DENIED'",
            [],
            |r: &Row| r.get(0),
        )?;

        Ok(VaultStats {
            total,
            allowed,
            denied,
        })
    }

    pub fn count(&self) -> Result<usize> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| anyhow!("Lock poisoned: {}", e))?;
        let count: usize =
            conn.query_row("SELECT COUNT(*) FROM audit_logs", [], |r: &Row| r.get(0))?;
        Ok(count)
    }

    pub fn db_path(&self) -> &str {
        &self.db_path
    }

    /// Retrieve recent audit logs for a specific namespace
    pub fn get_recent_by_namespace(
        &self,
        namespace: &str,
        limit: usize,
    ) -> Result<Vec<AuditEntry>> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| anyhow!("Lock poisoned: {}", e))?;

        let mut stmt = conn.prepare(
            "SELECT id, timestamp, event, tool_name, status, policy_match, payload, agent_id, namespace, anomaly_score, nearest_neighbor, fusion
             FROM audit_logs WHERE namespace = ?1 ORDER BY timestamp DESC LIMIT ?2"
        ).map_err(|e| anyhow!("Failed to prepare query: {}", e))?;

        let entries = stmt
            .query_map(params![namespace, limit], |row: &Row| {
                let id: String = row.get(0)?;
                let timestamp: String = row.get(1)?;
                let event: String = row.get(2)?;
                let tool_name: String = row.get(3)?;
                let status: String = row.get(4)?;
                let policy_match: Option<String> = row.get(5)?;
                let mut payload: Option<String> = row.get(6)?;
                let agent_id: Option<String> = row.get(7)?;
                let namespace: Option<String> = row.get(8)?;
                let anomaly_score: Option<f32> = row.get(9)?;
                let nearest_neighbor: Option<String> = row.get(10)?;
                let fusion: Option<String> = row.get(11)?;
                let fusion: Option<FusionEvidence> =
                    fusion.and_then(|s| serde_json::from_str(&s).ok());

                // Decrypt payload if key is available
                if let (Some(key_bytes), Some(p_enc)) = (&self.encryption_key, &payload) {
                    if p_enc.contains(':') {
                        let parts: Vec<&str> = p_enc.split(':').collect();
                        if parts.len() == 2 {
                            use base64::{engine::general_purpose, Engine as _};
                            if let (Ok(nonce_bytes), Ok(ciphertext)) = (
                                general_purpose::STANDARD.decode(parts[0]),
                                general_purpose::STANDARD.decode(parts[1]),
                            ) {
                                let cipher = Aes256Gcm::new(key_bytes.into());
                                let nonce = Nonce::from_slice(&nonce_bytes);
                                if let Ok(decrypted) = cipher.decrypt(nonce, ciphertext.as_slice())
                                {
                                    if let Ok(s) = String::from_utf8(decrypted) {
                                        payload = Some(s);
                                    }
                                }
                            }
                        }
                    }
                }

                Ok(AuditEntry {
                    id,
                    timestamp,
                    event,
                    tool_name,
                    status,
                    policy_match,
                    payload,
                    agent_id,
                    namespace,
                    anomaly_score,
                    nearest_neighbor,
                    fusion,
                })
            })
            .map_err(|e| anyhow!("Failed to execute query: {}", e))?;

        let mut result = Vec::new();
        for entry in entries {
            result.push(entry?);
        }

        Ok(result)
    }

    /// Retrieve stats for a specific namespace
    pub fn stats_by_namespace(&self, namespace: &str) -> Result<VaultStats> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| anyhow!("Lock poisoned: {}", e))?;
        let total: usize = conn.query_row(
            "SELECT COUNT(*) FROM audit_logs WHERE namespace = ?1",
            [namespace],
            |r: &Row| r.get(0),
        )?;
        let allowed: usize = conn.query_row(
            "SELECT COUNT(*) FROM audit_logs WHERE status = 'ALLOWED' AND namespace = ?1",
            [namespace],
            |r: &Row| r.get(0),
        )?;
        let denied: usize = conn.query_row(
            "SELECT COUNT(*) FROM audit_logs WHERE status = 'DENIED' AND namespace = ?1",
            [namespace],
            |r: &Row| r.get(0),
        )?;

        Ok(VaultStats {
            total,
            allowed,
            denied,
        })
    }

    /// Access the underlying database connection
    pub fn get_connection(&self) -> Arc<Mutex<Connection>> {
        Arc::clone(&self.conn)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn temp_db_path() -> String {
        format!("test_audit_{}.db", Uuid::new_v4())
    }

    #[test]
    fn test_audit_vault_creation() {
        let path = temp_db_path();
        let vault = AuditVault::new(&path, None).expect("Failed to create vault");
        assert_eq!(vault.count().unwrap(), 0);
        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_audit_entry_builder() {
        let entry = AuditEntry::new("TOOL_CALL", "read_file", "ALLOWED")
            .with_policy("base_security")
            .with_payload("{\"path\": \"/tmp/test\"}")
            .with_agent_id("agent-123");

        assert_eq!(entry.event, "TOOL_CALL");
        assert_eq!(entry.tool_name, "read_file");
        assert_eq!(entry.status, "ALLOWED");
        assert_eq!(entry.policy_match, Some("base_security".to_string()));
        assert!(entry.payload.is_some());
        assert_eq!(entry.agent_id, Some("agent-123".to_string()));
        assert!(entry.nearest_neighbor.is_none());
    }

    /// B-3: the fusion object must appear in serialized records ONLY when
    /// fusion actively participated (cameras/score/tau absent otherwise).
    #[test]
    fn fusion_evidence_serialized_only_when_fusion_active() {
        let plain =
            AuditEntry::new("TOOL_CALL", "bash", "DENIED").with_policy("restricted_commands");
        let plain_json = serde_json::to_string(&plain).unwrap();
        assert!(
            !plain_json.contains("fusion")
                && !plain_json.contains("cameras")
                && !plain_json.contains("neural_score")
                && !plain_json.contains("\"tau\""),
            "inactive fusion must not leak fields: {plain_json}"
        );

        let fused = AuditEntry::new("TOOL_CALL", "bash", "DENIED").with_fusion(FusionEvidence {
            cameras: vec!["rules".into(), "neural".into()],
            neural_score: 0.91,
            tau: 0.5,
            model_id: "zn-minilm-l6-v2-sec-1787490939".into(),
        });
        let fused_json = serde_json::to_string(&fused).unwrap();
        assert!(fused_json.contains(r#""cameras":["rules","neural"]"#));
        assert!(fused_json.contains(r#""neural_score":0.91"#));
        assert!(fused_json.contains(r#""tau":0.5"#));
        assert!(fused_json.contains("zn-minilm-l6-v2-sec-1787490939"));
    }

    /// B-3: fusion evidence survives the audit vault round-trip.
    #[test]
    fn fusion_evidence_persists_through_audit_vault() {
        let path = temp_db_path();
        let vault = AuditVault::new(&path, None).expect("Failed to create vault");
        vault
            .log(
                AuditEntry::new("TOOL_CALL", "bash", "DENIED").with_fusion(FusionEvidence {
                    cameras: vec!["neural".into()],
                    neural_score: 0.73,
                    tau: 0.5,
                    model_id: "m1".into(),
                }),
            )
            .expect("log fused entry");
        let recent = vault.get_recent(10).expect("get recent");
        let ev = recent[0].fusion.as_ref().expect("evidence round-tripped");
        assert_eq!(ev.cameras, vec!["neural".to_string()]);
        assert!((ev.neural_score - 0.73).abs() < 1e-6);
        assert_eq!(ev.tau, 0.5);
        // And an unfused entry stays unfused.
        vault
            .log(AuditEntry::new("TOOL_CALL", "ls", "ALLOWED"))
            .unwrap();
        let recent = vault.get_recent(10).unwrap();
        assert!(recent
            .iter()
            .find(|e| e.tool_name == "ls")
            .unwrap()
            .fusion
            .is_none());
        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_log_and_retrieve() {
        let path = temp_db_path();
        let vault = AuditVault::new(&path, None).expect("Failed to create vault");

        let entry = AuditEntry::new("TOOL_CALL", "delete_file", "DENIED");
        vault.log(entry).expect("Failed to log entry");

        assert_eq!(vault.count().unwrap(), 1);

        let recent = vault.get_recent(10).expect("Failed to get recent");
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].tool_name, "delete_file");
        assert_eq!(recent[0].status, "DENIED");

        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_stats() {
        let path = temp_db_path();
        let vault = AuditVault::new(&path, None).expect("Failed to create vault");

        // Log some entries
        vault
            .log(AuditEntry::new("TOOL_CALL", "read_file", "ALLOWED"))
            .unwrap();
        vault
            .log(AuditEntry::new("TOOL_CALL", "write_file", "ALLOWED"))
            .unwrap();
        vault
            .log(AuditEntry::new("TOOL_CALL", "delete_file", "DENIED"))
            .unwrap();

        let stats = vault.stats().expect("Failed to get stats");
        assert_eq!(stats.total, 3);
        assert_eq!(stats.allowed, 2);
        assert_eq!(stats.denied, 1);

        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_namespace_isolation() {
        let path = temp_db_path();
        let vault = AuditVault::new(&path, None).expect("Failed to create vault");

        // Log entries with different namespaces
        let mut entry1 = AuditEntry::new("TOOL_CALL", "read_file", "ALLOWED");
        entry1.namespace = Some("tenant_a".to_string());
        vault.log(entry1).unwrap();

        let mut entry2 = AuditEntry::new("TOOL_CALL", "write_file", "DENIED");
        entry2.namespace = Some("tenant_b".to_string());
        vault.log(entry2).unwrap();

        let tenant_a_logs = vault.get_recent_by_namespace("tenant_a", 10).unwrap();
        assert_eq!(tenant_a_logs.len(), 1);
        assert_eq!(tenant_a_logs[0].tool_name, "read_file");

        let tenant_b_stats = vault.stats_by_namespace("tenant_b").unwrap();
        assert_eq!(tenant_b_stats.total, 1);
        assert_eq!(tenant_b_stats.denied, 1);

        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_encryption_key_derivation() {
        let path = temp_db_path();
        // Use a simple passphrase for testing
        let vault = AuditVault::new(&path, Some("test_encryption_key"))
            .expect("Failed to create vault with encryption");

        // Log an entry with payload
        let entry = AuditEntry::new("TOOL_CALL", "secret_op", "ALLOWED")
            .with_payload("{\"secret\": \"hidden\"}");
        vault.log(entry).expect("Failed to log encrypted entry");

        // Retrieve and verify (payload should be decrypted)
        let recent = vault.get_recent(1).expect("Failed to get recent");
        assert_eq!(recent.len(), 1);
        assert!(recent[0].payload.is_some());
        assert!(recent[0].payload.as_ref().unwrap().contains("secret"));

        fs::remove_file(&path).ok();
    }
}
