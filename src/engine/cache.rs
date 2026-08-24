use crate::config::CachingConfig;
use dashmap::DashMap;
use std::time::{Duration, Instant};

struct CacheEntry {
    result: String,
    expiry: Instant,
}

/// Tool Result Cache (Exact Match)
pub struct ResultCache {
    /// agent_id:tool:args_hash -> Result
    cache: DashMap<String, CacheEntry>,
    config: CachingConfig,
}

impl ResultCache {
    pub fn new(config: CachingConfig) -> Self {
        Self {
            cache: DashMap::new(),
            config,
        }
    }

    /// Try to get a cached result
    pub fn get(&self, agent_id: &str, tool_name: &str, arguments: &str) -> Option<String> {
        if !self.config.enabled {
            return None;
        }

        let key = self.make_key(agent_id, tool_name, arguments);
        if let Some(entry) = self.cache.get(&key) {
            if entry.expiry > Instant::now() {
                return Some(entry.result.clone());
            } else {
                // Remove expired entry
                drop(entry);
                self.cache.remove(&key);
            }
        }
        None
    }

    /// Store a result in cache
    pub fn set(&self, agent_id: &str, tool_name: &str, arguments: &str, result: String) {
        if !self.config.enabled {
            return;
        }

        let key = self.make_key(agent_id, tool_name, arguments);
        let expiry = Instant::now() + Duration::from_secs(self.config.ttl_seconds);
        self.cache.insert(key, CacheEntry { result, expiry });
    }

    fn make_key(&self, agent_id: &str, tool_name: &str, arguments: &str) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        agent_id.hash(&mut hasher);
        tool_name.hash(&mut hasher);
        arguments.hash(&mut hasher);
        format!("{:x}", hasher.finish())
    }
}
