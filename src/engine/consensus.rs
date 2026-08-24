use crate::config::ConsensusConfig;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WitnessType {
    DeterministicPolicy(String), // WASM policy name
    NeuralJudge,
    HumanAdmin(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    pub witness: WitnessType,
    pub timestamp: DateTime<Utc>,
    pub metadata: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizableAction {
    pub id: String,
    pub agent_id: String,
    pub tool_name: String,
    pub arguments_hash: String, // Ensure request hasn't changed
    pub timestamp: DateTime<Utc>,
    pub signatures: Vec<Signature>,
    pub required_m: u32,
    pub status: ActionStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ActionStatus {
    Pending,
    Approved,
    Denied,
    Expired,
}

/// M-of-N Consensus Manager
pub struct ConsensusManager {
    /// Pending actions: action_id -> Action
    pending: DashMap<String, AuthorizableAction>,
    config: ConsensusConfig,
}

impl ConsensusManager {
    pub fn new(config: ConsensusConfig) -> Self {
        Self {
            pending: DashMap::new(),
            config,
        }
    }

    /// Check if a tool needs consensus and register it if so
    pub fn propose_action(
        &self,
        agent_id: &str,
        tool_name: &str,
        arguments: &str,
    ) -> Option<String> {
        if !self.config.enabled {
            return None;
        }

        // Check if tool is critical (supports wildcards)
        let is_critical = self.config.critical_tools.iter().any(|pattern| {
            if pattern.ends_with('*') {
                tool_name.starts_with(&pattern[..pattern.len() - 1])
            } else {
                tool_name == pattern
            }
        });

        if !is_critical {
            return None;
        }

        let args_hash = self.compute_hash(arguments);

        let action_id = Uuid::new_v4().to_string();
        let action = AuthorizableAction {
            id: action_id.clone(),
            agent_id: agent_id.to_string(),
            tool_name: tool_name.to_string(),
            arguments_hash: args_hash,
            timestamp: Utc::now(),
            signatures: Vec::new(),
            required_m: self.config.required_signatures,
            status: ActionStatus::Pending,
        };

        self.pending.insert(action_id.clone(), action);
        Some(action_id)
    }

    /// Add a signature to a pending action
    pub fn sign_action(
        &self,
        action_id: &str,
        witness: WitnessType,
    ) -> std::result::Result<ActionStatus, String> {
        let mut action = self
            .pending
            .get_mut(action_id)
            .ok_or_else(|| "Action not found or already processed".to_string())?;

        // Prevent duplicate signatures from same witness type
        if action
            .signatures
            .iter()
            .any(|s| match (&s.witness, &witness) {
                (WitnessType::DeterministicPolicy(n1), WitnessType::DeterministicPolicy(n2)) => {
                    n1 == n2
                }
                (WitnessType::NeuralJudge, WitnessType::NeuralJudge) => true,
                (WitnessType::HumanAdmin(u1), WitnessType::HumanAdmin(u2)) => u1 == u2,
                _ => false,
            })
        {
            return Ok(action.status.clone());
        }

        action.signatures.push(Signature {
            witness,
            timestamp: Utc::now(),
            metadata: None,
        });

        if action.signatures.len() >= action.required_m as usize {
            action.status = ActionStatus::Approved;
        }

        Ok(action.status.clone())
    }

    /// Deny an action
    pub fn deny_action(&self, action_id: &str, _reason: &str) -> std::result::Result<(), String> {
        let mut action = self
            .pending
            .get_mut(action_id)
            .ok_or_else(|| "Action not found".to_string())?;
        action.status = ActionStatus::Denied;
        Ok(())
    }

    /// Check if a specific action has been approved and matches the current request
    pub fn check_approval(&self, agent_id: &str, tool_name: &str, arguments: &str) -> bool {
        let hash = self.compute_hash(arguments);

        // Find matching approved action
        // Linear scan for simplicity; swap in a proper index if this path gets hot.
        let mut approved_id = None;
        for entry in self.pending.iter() {
            let action = entry.value();
            if action.status == ActionStatus::Approved
                && action.agent_id == agent_id
                && action.tool_name == tool_name
                && action.arguments_hash == hash
            {
                approved_id = Some(action.id.clone());
                break;
            }
        }

        if let Some(id) = approved_id {
            // "Consume" the approval so it can't be reused (TOCTOU fix)
            self.pending.remove(&id);
            return true;
        }

        false
    }

    /// Get current status of an action
    pub fn get_status(&self, action_id: &str) -> Option<ActionStatus> {
        self.pending.get(action_id).map(|a| a.status.clone())
    }

    /// List all pending actions
    pub fn list_pending(&self) -> Vec<AuthorizableAction> {
        self.pending
            .iter()
            .filter(|e| e.status == ActionStatus::Pending)
            .map(|e| e.value().clone())
            .collect()
    }

    fn compute_hash(&self, arguments: &str) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        arguments.hash(&mut hasher);
        format!("{:x}", hasher.finish())
    }
}
