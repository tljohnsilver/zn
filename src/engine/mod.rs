//! WASM Policy Engine Module
//!
//! Provides secure execution of WASM-based security policies with:
//! - Gas metering to prevent infinite loops
//! - Policy integrity verification via SHA-256 hashes
//! - Memory-safe communication with WASM modules

pub mod cache;
pub mod consensus;
pub mod loop_breaker;
pub mod neural;
pub mod reputation;
pub mod rules;
pub mod signing;
pub mod sync;
pub mod vision;
pub mod watcher;

use anyhow::{anyhow, Result};
use dashmap::DashMap;
use std::path::Path;
use std::sync::Arc;
use tracing::{error, info, warn};
use wasmtime::*;

struct ZnContext {
    memory_limit: usize,
    agent_id: Option<String>,
    state_store: Arc<DashMap<String, String>>,
}

impl ResourceLimiter for ZnContext {
    fn memory_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        Ok(desired <= self.memory_limit)
    }

    fn table_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        Ok(desired <= 1000)
    }
}

/// Configuration for the Zn Engine
pub struct ZnEngineConfig {
    /// Maximum fuel (gas) units for WASM execution
    pub gas_limit: u64,
    /// Maximum memory in bytes
    pub memory_limit: u64,
    /// Execution timeout in milliseconds
    pub timeout_ms: u64,
    /// Whitelist of allowed policy SHA-256 hashes (hex-encoded)
    /// If empty, all policies are allowed (not recommended for production)
    pub allowed_hashes: Vec<String>,
    /// Public key for Ed25519 signature verification (hex)
    pub signing_public_key: Option<String>,
}

/// WASM Policy Execution Engine
pub struct ZnEngine {
    engine: Engine,
    linker: Linker<ZnContext>,
    config: ZnEngineConfig,
    /// Registry of loaded policies (name -> Module)
    policies: DashMap<String, Arc<Module>>,
    /// Policy signature verifier
    verifier: signing::PolicyVerifier,
    /// Shared state store for policies
    state_store: Arc<DashMap<String, String>>,
}

impl ZnEngine {
    /// Create a new ZnEngine with the given configuration
    pub fn new(config: ZnEngineConfig) -> Result<Self> {
        let mut wasm_config = Config::new();
        wasm_config.consume_fuel(true);
        wasm_config.epoch_interruption(true);

        let engine = Engine::new(&wasm_config)?;

        // Start epoch ticker for timeouts
        let engine_for_ticker = engine.clone();
        std::thread::spawn(move || {
            loop {
                std::thread::sleep(std::time::Duration::from_millis(100)); // 100ms ticks
                engine_for_ticker.increment_epoch();
            }
        });

        let mut linker = Linker::<ZnContext>::new(&engine);
        let state_store = Arc::new(DashMap::new());

        // --- Host Functions ---

        // fn zn_state_set(key_ptr, key_len, val_ptr, val_len)
        linker.func_wrap(
            "env",
            "zn_state_set",
            move |mut caller: Caller<'_, ZnContext>,
                  k_ptr: u32,
                  k_len: u32,
                  v_ptr: u32,
                  v_len: u32| {
                let memory = match caller.get_export("memory") {
                    Some(Extern::Memory(m)) => m,
                    _ => return,
                };

                let mut key_buf = vec![0u8; k_len as usize];
                let mut val_buf = vec![0u8; v_len as usize];

                if memory.read(&caller, k_ptr as usize, &mut key_buf).is_ok()
                    && memory.read(&caller, v_ptr as usize, &mut val_buf).is_ok()
                {
                    if let (Ok(key), Ok(val)) =
                        (String::from_utf8(key_buf), String::from_utf8(val_buf))
                    {
                        caller.data().state_store.insert(key, val);
                    }
                }
            },
        )?;

        // fn zn_state_get(key_ptr, key_len, val_ptr, val_max_len) -> actual_len
        linker.func_wrap(
            "env",
            "zn_state_get",
            move |mut caller: Caller<'_, ZnContext>,
                  k_ptr: u32,
                  k_len: u32,
                  v_ptr: u32,
                  v_max_len: u32|
                  -> u32 {
                let memory = match caller.get_export("memory") {
                    Some(Extern::Memory(m)) => m,
                    _ => return 0,
                };

                let mut key_buf = vec![0u8; k_len as usize];
                if memory.read(&caller, k_ptr as usize, &mut key_buf).is_err() {
                    return 0;
                }

                let key = match String::from_utf8(key_buf) {
                    Ok(k) => k,
                    Err(_) => return 0,
                };

                // Copy value out of DashMap to avoid borrow conflicts
                let val_opt = caller.data().state_store.get(&key).map(|v| v.clone());

                if let Some(val) = val_opt {
                    let val_bytes = val.as_bytes();
                    let len = val_bytes.len() as u32;
                    let write_len = len.min(v_max_len);
                    if memory
                        .write(
                            &mut caller,
                            v_ptr as usize,
                            &val_bytes[..write_len as usize],
                        )
                        .is_ok()
                    {
                        return len;
                    }
                }
                0
            },
        )?;

        // fn zn_get_agent_id(ptr, max_len) -> actual_len
        linker.func_wrap(
            "env",
            "zn_get_agent_id",
            move |mut caller: Caller<'_, ZnContext>, ptr: u32, max_len: u32| -> u32 {
                let memory = match caller.get_export("memory") {
                    Some(Extern::Memory(m)) => m,
                    _ => return 0,
                };

                let agent_id_opt = caller.data().agent_id.clone();

                if let Some(agent_id) = agent_id_opt {
                    let bytes = agent_id.as_bytes();
                    let len = bytes.len() as u32;
                    let write_len = len.min(max_len);
                    if memory
                        .write(&mut caller, ptr as usize, &bytes[..write_len as usize])
                        .is_ok()
                    {
                        return len;
                    }
                }
                0
            },
        )?;

        if config.allowed_hashes.is_empty() {
            warn!("No allowed policy hashes configured - all policies will be accepted");
        } else {
            info!(
                "Policy engine initialized with {} allowed hashes",
                config.allowed_hashes.len()
            );
        }

        let verifier = signing::PolicyVerifier::new(config.signing_public_key.as_deref())?;

        Ok(Self {
            engine,
            linker,
            config,
            policies: DashMap::new(),
            verifier,
            state_store,
        })
    }

    /// Compute SHA-256 hash of data and return hex-encoded string
    fn compute_hash(data: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        hex::encode(result)
    }

    /// Verify policy integrity against allowed hashes
    fn verify_policy_integrity(&self, bytes: &[u8], path: &Path) -> Result<()> {
        if self.config.allowed_hashes.is_empty() {
            // No hash verification configured - allow all policies
            return Ok(());
        }

        let hash = Self::compute_hash(bytes);
        info!("Policy hash for {:?}: {}", path, hash);

        if self.config.allowed_hashes.contains(&hash) {
            info!("Policy {:?} passed integrity check", path);
            Ok(())
        } else {
            error!(
                "Policy {:?} failed integrity check. Hash {} not in allowed list",
                path, hash
            );
            Err(anyhow!(
                "Policy integrity check failed: hash {} not allowed",
                hash
            ))
        }
    }

    /// Load and register a WASM policy from file with integrity verification
    pub fn register_policy_from_file(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        let name = path
            .file_stem()
            .and_then(|s: &std::ffi::OsStr| s.to_str())
            .ok_or_else(|| anyhow!("Invalid policy filename"))?
            .to_string();

        let bytes = std::fs::read(path)
            .map_err(|e| anyhow!("Failed to read policy file {:?}: {}", path, e))?;

        // Verify integrity before loading
        self.verify_policy_integrity(&bytes, path)?;

        // Verify cryptographic signature if public key is configured
        self.verifier.verify(&bytes, path)?;

        let module = Module::new(&self.engine, bytes)
            .map_err(|e| anyhow!("Failed to compile WASM policy {:?}: {}", path, e))?;

        self.policies.insert(name.clone(), Arc::new(module));
        info!("Registered policy: {}", name);
        Ok(())
    }

    /// Registered policy count
    pub fn policy_count(&self) -> usize {
        self.policies.len()
    }

    /// Load all policies from a directory
    pub fn load_all_policies(&self, dir: impl AsRef<Path>) -> Result<()> {
        let dir = dir.as_ref();
        if !dir.exists() {
            std::fs::create_dir_all(dir)?;
        }

        for entry in walkdir::WalkDir::new(dir).max_depth(1) {
            let entry = entry?;
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "wasm") {
                if let Err(e) = self.register_policy_from_file(path) {
                    error!("Failed to load policy {:?}: {}", path, e);
                }
            }
        }
        Ok(())
    }

    /// Unregister a policy by name
    pub fn unregister_policy(&self, name: &str) {
        if self.policies.remove(name).is_some() {
            info!("Unregistered policy: {}", name);
        }
    }

    /// Get a policy by name
    pub fn _get_policy(&self, name: &str) -> Option<Arc<Module>> {
        self.policies.get(name).map(|m| Arc::clone(&m))
    }

    /// Check if target policy exists
    pub fn _has_policy(&self, name: &str) -> bool {
        self.policies.contains_key(name)
    }

    /// List all registered policies
    pub fn list_policies(&self) -> Vec<String> {
        self.policies
            .iter()
            .map(|entry| entry.key().clone())
            .collect()
    }

    /// Check a tool call against all registered policies
    /// Returns true only if ALL policies allow it.
    pub fn check_tool_call_all(
        &self,
        tool_name: &str,
        arguments: &str,
        agent_id: Option<String>,
    ) -> Result<bool> {
        if self.policies.is_empty() {
            // No policies = allow (default behavior)
            return Ok(true);
        }

        for entry in self.policies.iter() {
            let policy_name = entry.key();
            let module = entry.value();
            if !self.check_tool_call(module, tool_name, arguments, agent_id.clone())? {
                warn!("Policy '{}' DENIED tool call: {}", policy_name, tool_name);
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Load a policy from bytes (for testing or embedded policies)
    pub fn _load_policy_from_bytes(&self, bytes: &[u8], name: &str) -> Result<Module> {
        if !self.config.allowed_hashes.is_empty() {
            let hash = Self::compute_hash(bytes);
            if !self.config.allowed_hashes.contains(&hash) {
                return Err(anyhow!(
                    "Policy '{}' integrity check failed: hash {} not allowed",
                    name,
                    hash
                ));
            }
        }

        Module::new(&self.engine, bytes)
            .map_err(|e| anyhow!("Failed to compile WASM policy '{}': {}", name, e))
    }

    /// Check a tool call against a loaded policy module with optional agent identity
    ///
    /// Returns `true` if the tool call is allowed, `false` if denied.
    pub fn check_tool_call(
        &self,
        module: &Module,
        tool_name: &str,
        arguments: &str,
        agent_id: Option<String>,
    ) -> Result<bool> {
        let context = ZnContext {
            memory_limit: self.config.memory_limit as usize,
            agent_id,
            state_store: Arc::clone(&self.state_store),
        };
        let mut store = Store::new(&self.engine, context);
        store.limiter(|s| s);
        store.set_fuel(self.config.gas_limit)?;

        // Set timeout deadline (timeout_ms / 100ms per tick)
        let ticks = (self.config.timeout_ms / 100).max(1);
        store.set_epoch_deadline(ticks);

        let instance = self.linker.instantiate(&mut store, module)?;

        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or_else(|| anyhow!("Failed to find memory export"))?;

        let alloc = instance.get_typed_func::<u32, u32>(&mut store, "alloc")?;
        let dealloc = instance.get_typed_func::<(u32, u32), ()>(&mut store, "dealloc")?;
        let validate = instance
            .get_typed_func::<(u32, u32, u32, u32), i32>(&mut store, "validate_tool_call")?;

        // Write strings to WASM memory
        let name_bytes = tool_name.as_bytes();
        let name_len = name_bytes.len() as u32;
        let name_ptr = alloc.call(&mut store, name_len)?;

        // Check for allocation failure
        if name_ptr == 0 {
            return Err(anyhow!("WASM memory allocation failed for tool name"));
        }
        memory.write(&mut store, name_ptr as usize, name_bytes)?;

        let args_bytes = arguments.as_bytes();
        let args_len = args_bytes.len() as u32;
        let args_ptr = alloc.call(&mut store, args_len)?;

        // Check for allocation failure
        if args_ptr == 0 {
            // Cleanup name allocation before returning error
            let _ = dealloc.call(&mut store, (name_ptr, name_len));
            return Err(anyhow!("WASM memory allocation failed for arguments"));
        }
        memory.write(&mut store, args_ptr as usize, args_bytes)?;

        // Call the validation function
        let result = validate.call(&mut store, (name_ptr, name_len, args_ptr, args_len))?;

        // Cleanup memory
        let _ = dealloc.call(&mut store, (name_ptr, name_len));
        let _ = dealloc.call(&mut store, (args_ptr, args_len));

        // Log gas consumption for monitoring
        if let Ok(remaining) = store.get_fuel() {
            let consumed = self.config.gas_limit.saturating_sub(remaining);
            if consumed > self.config.gas_limit / 2 {
                warn!(
                    "High gas consumption for tool '{}': {} / {}",
                    tool_name, consumed, self.config.gas_limit
                );
            }
        }

        Ok(result == 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_hash_consistency() {
        let data = b"test policy content";
        let hash1 = ZnEngine::compute_hash(data);
        let hash2 = ZnEngine::compute_hash(data);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_compute_hash_different_data() {
        let hash1 = ZnEngine::compute_hash(b"data1");
        let hash2 = ZnEngine::compute_hash(b"data2");
        assert_ne!(hash1, hash2);
    }
}
