//! Configuration module for zn Security Proxy
//!
//! Provides unified configuration management from files, environment variables,
//! and CLI arguments with sensible defaults.

use crate::webhooks::WebhookConfig;
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Main configuration structure for zn
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZnConfig {
    /// Environment (development, production)
    #[serde(default = "default_environment")]
    pub environment: String,

    /// Server configuration
    #[serde(default)]
    pub server: ServerConfig,

    /// Security configuration
    #[serde(default)]
    pub security: SecurityConfig,

    /// Engine configuration
    #[serde(default)]
    pub engine: EngineConfig,

    /// Audit configuration
    #[serde(default)]
    pub audit: AuditConfig,

    /// Webhook configurations for alerts
    #[serde(default)]
    pub webhooks: Vec<WebhookConfig>,

    /// SIEM (Audit Export) configuration
    #[serde(default)]
    pub siem: SiemConfig,

    /// KMS (Key Management Service) configuration
    #[serde(default)]
    pub kms: KmsConfig,

    /// Neural configuration
    #[serde(default)]
    pub neural: NeuralConfig,

    /// Fusion Gate (B-3): rules ∥ neural head. Missing section = disabled.
    #[serde(default)]
    pub fusion: FusionConfig,

    /// Managed Rulesets (Cloudflare Style)
    #[serde(default)]
    pub managed_rules: ManagedRulesConfig,

    /// Recursive Loop Breaker
    #[serde(default)]
    pub loop_breaker: LoopBreakerConfig,

    /// Semantic Context Caching
    #[serde(default)]
    pub caching: CachingConfig,

    /// M-of-N Consensus Authorization
    #[serde(default)]
    pub consensus: ConsensusConfig,

    /// Guardrails configuration for paranoid modes
    #[serde(default)]
    pub guardrails: GuardrailsConfig,
}

impl Default for ZnConfig {
    fn default() -> Self {
        Self {
            environment: default_environment(),
            server: ServerConfig::default(),
            security: SecurityConfig::default(),
            engine: EngineConfig::default(),
            audit: AuditConfig::default(),
            webhooks: vec![],
            siem: SiemConfig::default(),
            kms: KmsConfig::default(),
            neural: NeuralConfig::default(),
            fusion: FusionConfig::default(),
            managed_rules: ManagedRulesConfig::default(),
            loop_breaker: LoopBreakerConfig::default(),
            caching: CachingConfig::default(),
            consensus: ConsensusConfig::default(),
            guardrails: GuardrailsConfig::default(),
        }
    }
}

fn default_environment() -> String {
    "development".to_string()
}

/// Server-related configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Management API port
    #[serde(default = "default_port")]
    pub port: u16,

    /// Bind address
    #[serde(default = "default_bind_address")]
    pub bind_address: String,

    /// Broadcast channel capacity
    #[serde(default = "default_channel_capacity")]
    pub channel_capacity: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            port: default_port(),
            bind_address: default_bind_address(),
            channel_capacity: default_channel_capacity(),
        }
    }
}

fn default_port() -> u16 {
    9090
}
fn default_bind_address() -> String {
    "127.0.0.1".to_string()
}
fn default_channel_capacity() -> usize {
    100
}

/// Security-related configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// API key for authentication (if None, auth is disabled - NOT recommended for production)
    pub api_key: Option<String>,

    /// Allowed CORS origins (if empty, only localhost is allowed)
    #[serde(default)]
    pub allowed_origins: Vec<String>,

    /// Enable rate limiting
    #[serde(default = "default_true")]
    pub rate_limit_enabled: bool,

    /// Maximum requests per minute per client
    #[serde(default = "default_rate_limit")]
    pub rate_limit_per_minute: u32,

    /// Multi-tenant namespace
    pub namespace: Option<String>,

    /// Secret for JWT validation
    pub jwt_secret: Option<String>,

    /// Token for MCP WebSocket authentication
    pub mcp_ws_token: Option<String>,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            api_key: std::env::var("ZN_API_KEY").ok(),
            allowed_origins: vec![
                "http://localhost:5173".to_string(),
                "http://localhost:9090".to_string(),
                "http://127.0.0.1:5173".to_string(),
                "http://127.0.0.1:9090".to_string(),
            ],
            rate_limit_enabled: true,
            rate_limit_per_minute: default_rate_limit(),
            namespace: std::env::var("ZN_NAMESPACE").ok(),
            jwt_secret: std::env::var("ZN_JWT_SECRET").ok(),
            mcp_ws_token: std::env::var("ZN_MCP_WS_TOKEN").ok(),
        }
    }
}

fn default_true() -> bool {
    true
}
fn default_rate_limit() -> u32 {
    60
}

/// WASM engine configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineConfig {
    /// Gas limit for WASM policy execution
    #[serde(default = "default_gas_limit")]
    pub gas_limit: u64,

    /// Max memory for WASM (MB)
    #[serde(default = "default_memory_limit")]
    pub memory_limit_mb: u64,

    /// Execution timeout (ms)
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,

    /// Allowed policy SHA-256 hashes (hex)
    #[serde(default)]
    pub allowed_policy_hashes: Vec<String>,

    /// Public key for Ed25519 signature verification (hex)
    pub signing_public_key: Option<String>,

    /// Policy directory path
    #[serde(default = "default_policy_dir")]
    pub policy_dir: String,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            gas_limit: default_gas_limit(),
            memory_limit_mb: default_memory_limit(),
            timeout_ms: default_timeout(),
            allowed_policy_hashes: vec![],
            signing_public_key: None,
            policy_dir: default_policy_dir(),
        }
    }
}

fn default_gas_limit() -> u64 {
    10_000_000
}
fn default_memory_limit() -> u64 {
    128
} // 128 MB
fn default_timeout() -> u64 {
    1000
} // 1 second
fn default_policy_dir() -> String {
    "./policies_bin".to_string()
}

/// Audit configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    /// Database file path
    #[serde(default = "default_db_path")]
    pub db_path: String,

    /// Maximum logs to keep in memory for dashboard
    #[serde(default = "default_max_logs")]
    pub max_logs_in_memory: usize,

    /// Enable database encryption (requires encryption key)
    #[serde(default)]
    pub encryption_enabled: bool,

    /// Database encryption key
    pub encryption_key: Option<String>,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            db_path: default_db_path(),
            max_logs_in_memory: default_max_logs(),
            encryption_enabled: false,
            encryption_key: std::env::var("ZN_DB_KEY").ok(),
        }
    }
}

fn default_db_path() -> String {
    "zn.db".to_string()
}
fn default_max_logs() -> usize {
    50
}

/// SIEM (External Audit Export) configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SiemConfig {
    /// External SIEM endpoint (HTTP/HTTPS)
    pub endpoint: Option<String>,
    /// Authentication token for SIEM
    pub token: Option<String>,
    /// Export batch size
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,
}

fn default_batch_size() -> usize {
    10
}

/// KMS Configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KmsConfig {
    /// Type of KMS to use (local, aws, gcp, vaults)
    #[serde(default = "default_kms_type")]
    pub kms_type: String,
    /// Key ID / ARN
    pub key_id: Option<String>,
    /// Region (if applicable)
    pub region: Option<String>,
}

impl Default for KmsConfig {
    fn default() -> Self {
        Self {
            kms_type: default_kms_type(),
            key_id: std::env::var("ZN_KMS_KEY_ID").ok(),
            region: std::env::var("ZN_KMS_REGION").ok(),
        }
    }
}

fn default_kms_type() -> String {
    "local".to_string()
}

/// Neural / AI Security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NeuralConfig {
    /// Enable neural analysis
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Anomaly score threshold for blocking (0.0 - 5.0+)
    /// Typical L2 distance for all-MiniLM is < 1.0 for similar.
    #[serde(default = "default_neural_threshold")]
    pub threshold: f32,

    /// If true, block requests that exceed threshold
    #[serde(default = "default_false")]
    pub active_blocking: bool,

    /// Classifier probability threshold (0.0 - 1.0) for the fused decision.
    /// Only used when the model ships a `head.json`; anomaly-only models ignore it.
    #[serde(default = "default_classifier_threshold")]
    pub classifier_threshold: f32,

    /// Embedding model ID to use
    #[serde(default = "default_neural_model")]
    pub model_id: String,

    /// Local cache directory for the model files (~/ expanded; ZN_NEURAL_MODEL_PATH overrides)
    #[serde(default = "default_neural_model_path")]
    pub model_path: String,

    /// Embedding dimension (must match the model, e.g. 384 for all-MiniLM-L6-v2)
    #[serde(default = "default_neural_dim")]
    pub dim: usize,
}

impl Default for NeuralConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            threshold: default_neural_threshold(),
            active_blocking: false, // Default to Shadow Mode (false)
            classifier_threshold: default_classifier_threshold(),
            model_id: default_neural_model(),
            model_path: default_neural_model_path(),
            dim: default_neural_dim(),
        }
    }
}

fn default_neural_threshold() -> f32 {
    1.2
}
fn default_classifier_threshold() -> f32 {
    0.5
}
fn default_neural_model() -> String {
    "all-MiniLM-L6-v2".to_string()
}
fn default_neural_model_path() -> String {
    "~/.zn/models/all-MiniLM-L6-v2".to_string()
}
fn default_neural_dim() -> usize {
    384
}
fn default_false() -> bool {
    false
}

/// Fusion Gate (B-3): block iff rules hit OR neural score >= tau.
///
/// A missing `[fusion]` section deserializes to `enabled: false`, which must
/// degrade EXACTLY to the rules-only gate (regression-guarded in evals).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FusionConfig {
    /// Fusion off by default; opt-in via config.
    #[serde(default)]
    pub enabled: bool,

    /// Neural camera threshold on the head probability in [0, 1]. Shipped
    /// default is the offline value maximizing fused recall subject to fused
    /// FPR <= 0.014 over the exported fixture (see README "Gate" section).
    #[serde(default = "default_fusion_tau")]
    pub tau: f32,

    /// Model dir holding `model_int8.onnx` (or `model.onnx`) + `tokenizer.json`
    /// + `head.json` (~/ expanded).
    #[serde(default = "default_fusion_model_path")]
    pub model_path: String,

    /// Model version id; must match the exported score fixture's `model_id`.
    #[serde(default = "default_fusion_model_id")]
    pub model_id: String,
}

impl Default for FusionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            tau: default_fusion_tau(),
            model_path: default_fusion_model_path(),
            model_id: default_fusion_model_id(),
        }
    }
}

fn default_fusion_tau() -> f32 {
    // Offline sweep over evals/fixtures/head_scores.json (ml/eval.py
    // --export-scores): lowest tau maximizing fused recall subject to fused
    // FPR <= 1.4%. Alternatives in README "Gate" section.
    0.623
}
fn default_fusion_model_path() -> String {
    "~/.zn/models/zn-minilm-l6-v2-sec-1787474325".to_string()
}
fn default_fusion_model_id() -> String {
    // Gate-valid run with a candle-evaluable export; the newest dir
    // (1787490939) is a 100-vector smoke run whose re-export candle-onnx
    // 0.9.2 cannot evaluate (see README "Gate" section).
    "zn-minilm-l6-v2-sec-1787474325".to_string()
}

/// Managed Rulesets Configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagedRulesConfig {
    /// Enable PII (Personally Identifiable Information) Redaction
    #[serde(default = "default_true")]
    pub pii_redaction: bool,
    /// Enable LFI (Local File Inclusion) Protection
    #[serde(default = "default_true")]
    pub lfi_protection: bool,
    /// Enable SQL Injection Protection
    #[serde(default = "default_true")]
    pub sql_injection: bool,
    /// Enable Prompt Injection Protection
    #[serde(default = "default_true")]
    pub prompt_injection: bool,
    /// Block common dangerous system commands (rm, format, etc)
    #[serde(default = "default_true")]
    pub restricted_commands: bool,
    /// Multimodal: OCR and Visual PII Redaction
    #[serde(default = "default_false")]
    pub visual_pii_redaction: bool,
}

impl Default for ManagedRulesConfig {
    fn default() -> Self {
        Self {
            pii_redaction: true,
            lfi_protection: true,
            sql_injection: true,
            prompt_injection: true,
            restricted_commands: true,
            visual_pii_redaction: false,
        }
    }
}

/// Loop Breaker Configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoopBreakerConfig {
    /// Enable detection of infinite tool loops
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Maximum number of times the same tool/args can be called
    #[serde(default = "default_max_repeats")]
    pub max_repeats: usize,
    /// Time window for repeat detection (seconds)
    #[serde(default = "default_window")]
    pub window_seconds: u64,
}

impl Default for LoopBreakerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_repeats: 3,
            window_seconds: 60,
        }
    }
}

fn default_max_repeats() -> usize {
    3
}
fn default_window() -> u64 {
    60
}

/// Caching Configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachingConfig {
    /// Enable tool result caching
    #[serde(default = "default_false")]
    pub enabled: bool,
    /// Cache Time-To-Live (seconds)
    #[serde(default = "default_ttl")]
    pub ttl_seconds: u64,
}

impl Default for CachingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            ttl_seconds: 300, // 5 minutes
        }
    }
}

fn default_ttl() -> u64 {
    300
}

/// Consensus Authorization Configuration (M-of-N)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusConfig {
    /// Enable multi-sig consensus for critical tools
    #[serde(default = "default_false")]
    pub enabled: bool,
    /// List of tool patterns that require consensus (e.g., "admin:*", "delete_file")
    #[serde(default)]
    pub critical_tools: Vec<String>,
    /// Number of required signatures (M)
    #[serde(default = "default_m")]
    pub required_signatures: u32,
    /// Allow neural core to act as one witness if risk is low
    #[serde(default = "default_true")]
    pub neural_as_witness: bool,
}

impl Default for ConsensusConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            critical_tools: Vec::new(),
            required_signatures: 2,
            neural_as_witness: true,
        }
    }
}

fn default_m() -> u32 {
    2
}

/// Guardrails configuration for paranoid modes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardrailsConfig {
    /// Default mode: alert-only (no blocking) for neural anomalies
    #[serde(default = "default_true")]
    pub alert_only: bool,
    /// Paranoia level (1-5) controls thresholds and rollback aggressiveness
    #[serde(default = "default_paranoia_level")]
    pub paranoia_level: u8,
    /// Minimum samples before FPR guard evaluates rollback
    #[serde(default = "default_min_samples")]
    pub min_samples: u64,
    /// FPR margin (control + margin triggers rollback)
    #[serde(default = "default_fpr_margin")]
    pub fpr_margin: f64,
    /// Enable nearest-neighbor audit logging
    #[serde(default = "default_true")]
    pub nearest_neighbor_audit: bool,
}

impl Default for GuardrailsConfig {
    fn default() -> Self {
        Self {
            alert_only: true,
            paranoia_level: default_paranoia_level(),
            min_samples: default_min_samples(),
            fpr_margin: default_fpr_margin(),
            nearest_neighbor_audit: true,
        }
    }
}

fn default_paranoia_level() -> u8 {
    1
}

fn default_min_samples() -> u64 {
    50
}

fn default_fpr_margin() -> f64 {
    0.02
}

impl ZnConfig {
    /// Load configuration from file with environment variable overrides
    pub fn load(path: Option<&Path>) -> Result<Self> {
        let mut config = if let Some(p) = path {
            if p.exists() {
                let content = std::fs::read_to_string(p)?;
                if p.extension().map(|e| e == "json").unwrap_or(false) {
                    serde_json::from_str(&content)?
                } else {
                    // Default to JSON if extension is unknown
                    serde_json::from_str(&content).unwrap_or_default()
                }
            } else {
                Self::default()
            }
        } else {
            // Try to load from default locations
            let config_options = ["zn.json", "zn.config.json", ".zn.json"];
            let mut found = None;
            for option in config_options {
                if Path::new(option).exists() {
                    let content = std::fs::read_to_string(option)?;
                    found = Some(serde_json::from_str(&content)?);
                    break;
                }
            }
            found.unwrap_or_default()
        };

        // Override with environment variables
        config.apply_env_overrides();

        Ok(config)
    }

    /// Apply environment variable overrides
    fn apply_env_overrides(&mut self) {
        if let Ok(env) = std::env::var("ZN_ENV") {
            self.environment = env;
        }

        if let Ok(port) = std::env::var("ZN_PORT") {
            if let Ok(p) = port.parse() {
                self.server.port = p;
            }
        }

        if let Ok(key) = std::env::var("ZN_API_KEY") {
            self.security.api_key = Some(key);
        }

        if let Ok(ns) = std::env::var("ZN_NAMESPACE") {
            self.security.namespace = Some(ns);
        }

        if let Ok(jwt) = std::env::var("ZN_JWT_SECRET") {
            self.security.jwt_secret = Some(jwt);
        }

        if let Ok(origins) = std::env::var("ZN_ALLOWED_ORIGINS") {
            self.security.allowed_origins =
                origins.split(',').map(|s| s.trim().to_string()).collect();
        }

        if let Ok(token) = std::env::var("ZN_MCP_WS_TOKEN") {
            self.security.mcp_ws_token = Some(token);
        }

        if let Ok(gas) = std::env::var("ZN_GAS_LIMIT") {
            if let Ok(g) = gas.parse() {
                self.engine.gas_limit = g;
            }
        }

        if let Ok(mem) = std::env::var("ZN_MEMORY_LIMIT") {
            if let Ok(m) = mem.parse() {
                self.engine.memory_limit_mb = m;
            }
        }

        if let Ok(to) = std::env::var("ZN_TIMEOUT") {
            if let Ok(t) = to.parse() {
                self.engine.timeout_ms = t;
            }
        }

        if let Ok(hashes) = std::env::var("ZN_POLICY_HASHES") {
            self.engine.allowed_policy_hashes = hashes.split(',').map(|s| s.to_string()).collect();
        }

        if let Ok(key) = std::env::var("ZN_SIGNING_PUBLIC_KEY") {
            self.engine.signing_public_key = Some(key);
        }

        if let Ok(db) = std::env::var("ZN_DB_PATH") {
            self.audit.db_path = db;
        }

        if let Ok(key) = std::env::var("ZN_DB_KEY") {
            self.audit.encryption_key = Some(key);
            self.audit.encryption_enabled = true;
        }

        if let Ok(endpoint) = std::env::var("ZN_SIEM_ENDPOINT") {
            self.siem.endpoint = Some(endpoint);
        }

        if let Ok(token) = std::env::var("ZN_SIEM_TOKEN") {
            self.siem.token = Some(token);
        }

        if let Ok(kms_type) = std::env::var("ZN_KMS_TYPE") {
            self.kms.kms_type = kms_type;
        }

        if let Ok(key_id) = std::env::var("ZN_KMS_KEY_ID") {
            self.kms.key_id = Some(key_id);
        }

        if let Ok(neural_enabled) = std::env::var("ZN_NEURAL_ENABLED") {
            self.neural.enabled = neural_enabled.parse().unwrap_or(true);
        }

        if let Ok(neural_threshold) = std::env::var("ZN_NEURAL_THRESHOLD") {
            if let Ok(t) = neural_threshold.parse() {
                self.neural.threshold = t;
            }
        }

        if let Ok(active_blocking) = std::env::var("ZN_NEURAL_BLOCKING") {
            self.neural.active_blocking = active_blocking.parse().unwrap_or(false);
        }

        if let Ok(alert_only) = std::env::var("ZN_GUARDRAILS_ALERT_ONLY") {
            self.guardrails.alert_only = alert_only.parse().unwrap_or(true);
        }

        if let Ok(paranoia) = std::env::var("ZN_PARANOIA_LEVEL") {
            if let Ok(lvl) = paranoia.parse::<u8>() {
                self.guardrails.paranoia_level = lvl.clamp(1, 5);
            }
        }

        if let Ok(min_s) = std::env::var("ZN_MIN_SAMPLES") {
            if let Ok(v) = min_s.parse::<u64>() {
                self.guardrails.min_samples = v;
            }
        }

        if let Ok(margin) = std::env::var("ZN_FPR_MARGIN") {
            if let Ok(m) = margin.parse::<f64>() {
                self.guardrails.fpr_margin = m;
            }
        }

        if let Ok(nn_audit) = std::env::var("ZN_NEAREST_NEIGHBOR_AUDIT") {
            self.guardrails.nearest_neighbor_audit = nn_audit.parse().unwrap_or(true);
        }
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<()> {
        if self.security.api_key.is_none() && self.environment == "production" {
            tracing::warn!("No API key configured in production - Management API is unprotected!");
        }

        if self.security.allowed_origins.is_empty() {
            tracing::info!("No CORS origins configured - only localhost will be allowed");
        }

        if self.environment == "production"
            && (!self.audit.encryption_enabled || self.audit.encryption_key.is_none())
        {
            return Err(anyhow!(
                "Audit log encryption is MANDATORY in production. Please set ZN_DB_KEY."
            ));
        }

        Ok(())
    }

    /// Get neural blocking mode based on paranoia level and alert_only
    pub fn is_neural_blocking(&self) -> bool {
        !self.guardrails.alert_only && self.neural.active_blocking
    }

    /// Get paranoia-adjusted threshold multiplier
    pub fn paranoia_threshold_multiplier(&self) -> f32 {
        match self.guardrails.paranoia_level {
            1 => 1.5, // relaxed
            2 => 1.2, // normal
            3 => 1.0, // balanced
            4 => 0.8, // strict
            5 => 0.6, // paranoid
            _ => 1.0,
        }
    }

    /// Get paranoia-adjusted classifier threshold
    pub fn paranoia_classifier_threshold(&self) -> f32 {
        match self.guardrails.paranoia_level {
            1 => 0.7, // relaxed
            2 => 0.6, // normal
            3 => 0.5, // balanced
            4 => 0.4, // strict
            5 => 0.3, // paranoid
            _ => 0.5,
        }
    }
}
