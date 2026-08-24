use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Protocol Constants
pub const METHOD_SEND: &str = "tasks/send";
pub const METHOD_GET: &str = "tasks/get";
pub const METHOD_LIST: &str = "tasks/list";
pub const METHOD_CANCEL: &str = "tasks/cancel";

/// A2A JSON-RPC Request Params
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct A2AParams {
    /// Target Agent ID or Topic
    pub recipient: String,
    /// The actual task payload
    pub task: Value,
    /// Optional urgency level (low, normal, high, critical)
    pub priority: Option<String>,
    /// Optional correlation ID for threads
    pub thread_id: Option<String>,
}

/// Helper to validate if a string is a known A2A method
pub fn is_a2a_method(method: &str) -> bool {
    matches!(
        method,
        METHOD_SEND | METHOD_GET | METHOD_LIST | METHOD_CANCEL
    )
}

/// Resolves the "virtual tool name" for policy checking
///
/// Strategies:
/// - Exact Route: a2a:send:finance-agent
/// - Action Only: a2a:send
/// - Wildcard Recipient: a2a:send:*
pub fn resolve_policy_context(method: &str, params: &Value) -> String {
    let action = method.trim_start_matches("tasks/");

    // Extract recipient safely
    let recipient = params
        .get("recipient")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty());

    match recipient {
        Some(target) => format!("a2a:{}:{}", action, target),
        None => format!("a2a:{}", action),
    }
}
