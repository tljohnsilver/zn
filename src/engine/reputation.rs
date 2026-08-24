//! Active Defense & Reputation Module
//!
//! Tracks agent behavior over time and enforces automated defense mechanisms (bans, throttling)
//! when threat thresholds are exceeded.
//!
//! "The Immune System of the Agent Mesh"

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

const MAX_SCORE: i32 = 100;
const INITIAL_SCORE: i32 = 50;
const BAN_THRESHOLD: i32 = 0; // If score drops below 0, ban agent
const BAN_DURATION_MINUTES: i64 = 10;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AgentStatus {
    Trusted,    // Score > 80
    Neutral,    // Score 20-80
    Suspicious, // Score 0-20
    Banned,     // Score < 0
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationScore {
    pub agent_id: String,
    pub score: i32,
    pub status: AgentStatus,
    pub total_calls: u64,
    pub blocked_calls: u64,
    pub last_violation: Option<DateTime<Utc>>,
    pub banned_until: Option<DateTime<Utc>>,
    pub violations: Vec<String>, // Log of last 5 violations
}

impl Default for ReputationScore {
    fn default() -> Self {
        Self {
            agent_id: "unknown".to_string(),
            score: INITIAL_SCORE,
            status: AgentStatus::Neutral,
            total_calls: 0,
            blocked_calls: 0,
            last_violation: None,
            banned_until: None,
            violations: Vec::new(),
        }
    }
}

pub struct ReputationSystem {
    // Map of AgentID -> Score
    scores: Arc<RwLock<HashMap<String, ReputationScore>>>,
}

impl ReputationSystem {
    pub fn new() -> Self {
        Self {
            scores: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl Default for ReputationSystem {
    fn default() -> Self {
        Self::new()
    }
}

impl ReputationSystem {
    /// Get current status of an agent (Auth Check)
    pub fn check_agent_status(&self, agent_id: &str) -> Result<(), String> {
        let scores = self.scores.read().unwrap();
        if let Some(entry) = scores.get(agent_id) {
            if entry.status == AgentStatus::Banned {
                if let Some(ban_end) = entry.banned_until {
                    if Utc::now() < ban_end {
                        return Err(format!(
                            "Agent BANNED active defense system until {}",
                            ban_end
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    /// Record a clean, allowed call
    pub fn record_success(&self, agent_id: &str) {
        let mut scores = self.scores.write().unwrap();
        let entry = scores
            .entry(agent_id.to_string())
            .or_insert(ReputationScore {
                agent_id: agent_id.to_string(),
                ..Default::default()
            });

        // Auto-unban check
        if entry.status == AgentStatus::Banned {
            if let Some(ban_end) = entry.banned_until {
                if Utc::now() > ban_end {
                    entry.status = AgentStatus::Suspicious; // Unban to suspicious
                    entry.score = 10; // Reset to low score
                    entry.banned_until = None;
                }
            }
        }

        entry.total_calls += 1;
        entry.score = (entry.score + 1).min(MAX_SCORE);
        entry.update_status();
    }

    /// Record a security violation (Block)
    pub fn record_violation(&self, agent_id: &str, reason: &str, severity: i32) {
        let mut scores = self.scores.write().unwrap();
        let entry = scores
            .entry(agent_id.to_string())
            .or_insert(ReputationScore {
                agent_id: agent_id.to_string(),
                ..Default::default()
            });

        entry.total_calls += 1;
        entry.blocked_calls += 1;
        entry.score -= severity;
        entry.last_violation = Some(Utc::now());

        // Keep last 5 violations
        entry.violations.push(reason.to_string());
        if entry.violations.len() > 5 {
            entry.violations.remove(0);
        }

        entry.update_status();
    }

    /// Get all scores for dashboard
    pub fn all_scores(&self) -> HashMap<String, ReputationScore> {
        self.scores.read().unwrap().clone()
    }
}

impl ReputationScore {
    fn update_status(&mut self) {
        if self.score <= BAN_THRESHOLD {
            if self.status != AgentStatus::Banned {
                self.status = AgentStatus::Banned;
                self.banned_until = Some(Utc::now() + Duration::minutes(BAN_DURATION_MINUTES));
            }
        } else if self.score < 20 {
            self.status = AgentStatus::Suspicious;
        } else if self.score > 80 {
            self.status = AgentStatus::Trusted;
        } else {
            self.status = AgentStatus::Neutral;
        }
    }
}
