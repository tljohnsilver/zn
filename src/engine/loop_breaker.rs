use crate::config::LoopBreakerConfig;
use dashmap::DashMap;
use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Entry in the action history
struct ActionEntry {
    tool_name: String,
    arguments_hash: u64,
    timestamp: Instant,
}

/// Recursive Loop Breaker Engine
pub struct LoopBreaker {
    /// History per agent: agent_id -> VecDeque of recent actions
    history: DashMap<String, VecDeque<ActionEntry>>,
    config: LoopBreakerConfig,
}

impl LoopBreaker {
    pub fn new(config: LoopBreakerConfig) -> Self {
        Self {
            history: DashMap::new(),
            config,
        }
    }

    /// Check if a tool call is part of an infinite loop
    pub fn check_and_record(
        &self,
        agent_id: &str,
        tool_name: &str,
        arguments: &str,
    ) -> std::result::Result<(), String> {
        if !self.config.enabled {
            return Ok(());
        }

        let normalized_args = self.normalize_arguments(arguments);
        let hash = self.compute_hash(&normalized_args);
        let now = Instant::now();
        let window = Duration::from_secs(self.config.window_seconds);

        let mut agent_history = self
            .history
            .entry(agent_id.to_string())
            .or_insert_with(VecDeque::new);

        // Cleanup old entries
        while agent_history
            .front()
            .is_some_and(|e| now.duration_since(e.timestamp) > window)
        {
            agent_history.pop_front();
        }

        // Count repeats
        let repeats = agent_history
            .iter()
            .filter(|e| e.tool_name == tool_name && e.arguments_hash == hash)
            .count();

        if repeats >= self.config.max_repeats {
            return Err(format!(
                "Recursive loop detected: Tool '{}' called {} times with identical arguments in {}s",
                tool_name, repeats + 1, self.config.window_seconds
            ));
        }

        // Record current action
        agent_history.push_back(ActionEntry {
            tool_name: tool_name.to_string(),
            arguments_hash: hash,
            timestamp: now,
        });

        Ok(())
    }

    fn compute_hash(&self, arguments: &str) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        arguments.hash(&mut hasher);
        hasher.finish()
    }

    /// Normalize JSON strings to a canonical representation to prevent bypasses
    fn normalize_arguments(&self, arguments: &str) -> String {
        match serde_json::from_str::<serde_json::Value>(arguments) {
            Ok(v) => v.to_string(), // serde_json::to_string() produces a compact, sorted key-order JSON
            Err(_) => arguments.to_string(), // Fallback for non-JSON content
        }
    }
}
