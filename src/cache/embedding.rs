use lru::LruCache;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Embedding cache entry with TTL support
#[derive(Debug, Clone)]
pub struct CacheEntry {
    pub value: Vec<f32>,
    pub created_at: Instant,
    pub expires_at: Instant,
}

impl CacheEntry {
    pub fn new(value: Vec<f32>, ttl: Duration) -> Self {
        let now = Instant::now();
        Self {
            value,
            created_at: now,
            expires_at: now + ttl,
        }
    }

    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }
}

/// Thread-safe embedding cache with TTL and LRU eviction
pub struct EmbeddingCache {
    cache: Arc<Mutex<LruCache<String, CacheEntry>>>,
    ttl: Duration,
    max_size: usize,
}

impl EmbeddingCache {
    /// Create a new cache with specified TTL and max size
    pub fn new(ttl_seconds: u64, max_size: usize) -> Self {
        let ttl = Duration::from_secs(ttl_seconds);
        let cache = LruCache::new(NonZeroUsize::new(max_size).unwrap());
        Self {
            cache: Arc::new(Mutex::new(cache)),
            ttl,
            max_size,
        }
    }

    fn key(model_id: &str, text: &str) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut h = DefaultHasher::new();
        text.hash(&mut h);
        format!("{model_id}:{:016x}", h.finish())
    }

    /// Get an embedding from cache, returns None if not found or expired
    pub fn get(&self, model_id: &str, text: &str) -> Option<Vec<f32>> {
        let key = Self::key(model_id, text);
        let mut cache = self.cache.lock().unwrap();

        if let Some(entry) = cache.get(&key) {
            if entry.is_expired() {
                cache.pop(&key);
                return None;
            }
            return Some(entry.value.clone());
        }

        None
    }

    /// Insert an embedding into cache
    pub fn insert(&self, model_id: &str, text: &str, embedding: Vec<f32>) {
        let key = Self::key(model_id, text);
        let entry = CacheEntry::new(embedding, self.ttl);
        let mut cache = self.cache.lock().unwrap();
        cache.put(key, entry);
    }

    /// Clear all expired entries
    pub fn cleanup_expired(&self) {
        let mut cache = self.cache.lock().unwrap();
        let expired: Vec<String> = cache
            .iter()
            .filter(|(_, entry)| entry.is_expired())
            .map(|(key, _)| key.clone())
            .collect();

        for key in expired {
            cache.pop(&key);
        }
    }

    /// Get cache statistics
    pub fn stats(&self) -> CacheStats {
        let cache = self.cache.lock().unwrap();
        CacheStats {
            size: cache.len(),
            max_size: self.max_size,
            ttl_seconds: self.ttl.as_secs(),
        }
    }

    /// Clear the entire cache
    pub fn clear(&self) {
        let mut cache = self.cache.lock().unwrap();
        cache.clear();
    }
}

/// Cache statistics
#[derive(Debug, Clone)]
pub struct CacheStats {
    pub size: usize,
    pub max_size: usize,
    pub ttl_seconds: u64,
}

impl Default for EmbeddingCache {
    fn default() -> Self {
        Self::new(300, 10000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_cache_insert_and_get() {
        let cache = EmbeddingCache::new(300, 100);
        let text = "test text";
        let embedding = vec![1.0, 2.0, 3.0];

        cache.insert("m1", text, embedding.clone());
        let result = cache.get("m1", text);

        assert!(result.is_some());
        assert_eq!(result.unwrap(), embedding);
    }

    #[test]
    fn test_cache_miss() {
        let cache = EmbeddingCache::new(300, 100);

        assert!(cache.get("m1", "nonexistent").is_none());
    }

    #[test]
    fn test_cache_ttl_expiration() {
        let cache = EmbeddingCache::new(1, 100);
        let text = "test text";
        let embedding = vec![1.0, 2.0, 3.0];

        cache.insert("m1", text, embedding);
        assert!(cache.get("m1", text).is_some());

        thread::sleep(Duration::from_secs(2));
        assert!(cache.get("m1", text).is_none());
    }

    #[test]
    fn test_cache_lru_eviction() {
        let cache = EmbeddingCache::new(300, 3);

        for i in 0..5 {
            cache.insert("m1", &format!("text{i}"), vec![i as f32; 3]);
        }

        assert!(cache.get("m1", "text0").is_none());
        assert!(cache.get("m1", "text1").is_none());
        assert!(cache.get("m1", "text2").is_some());
        assert!(cache.get("m1", "text3").is_some());
        assert!(cache.get("m1", "text4").is_some());
    }

    #[test]
    fn test_cache_stats() {
        let cache = EmbeddingCache::new(300, 100);

        let stats = cache.stats();
        assert_eq!(stats.size, 0);
        assert_eq!(stats.max_size, 100);
        assert_eq!(stats.ttl_seconds, 300);
    }

    #[test]
    fn test_cache_clear() {
        let cache = EmbeddingCache::new(300, 100);

        cache.insert("m1", "text1", vec![1.0]);
        cache.insert("m1", "text2", vec![2.0]);

        assert_eq!(cache.stats().size, 2);

        cache.clear();

        assert_eq!(cache.stats().size, 0);
    }

    #[test]
    fn different_model_id_is_a_miss() {
        let cache = EmbeddingCache::new(300, 100);
        cache.insert("model-a", "same text", vec![1.0, 2.0]);
        assert!(cache.get("model-a", "same text").is_some());
        assert!(cache.get("model-b", "same text").is_none());
    }
}
