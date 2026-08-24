//! Webhook Alerts Module
//!
//! Sends real-time alerts to external services when security events occur.
//! Supports Slack, Discord, and generic webhook endpoints.

use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tracing::{error, info, warn};

/// Webhook configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WebhookConfig {
    /// Webhook URL to send alerts to
    pub url: String,
    /// Type of webhook (slack, discord, generic)
    #[serde(default = "default_webhook_type")]
    pub webhook_type: WebhookType,
    /// Only send alerts for these event types (empty = all)
    #[serde(default)]
    pub event_filter: Vec<String>,
    /// Only send alerts for these statuses (e.g., ["DENIED"])
    #[serde(default)]
    pub status_filter: Vec<String>,
    /// Whether this webhook is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_webhook_type() -> WebhookType {
    WebhookType::Generic
}

fn default_true() -> bool {
    true
}

/// Type of webhook endpoint
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum WebhookType {
    Slack,
    Discord,
    Generic,
}

/// Alert payload to send via webhook
#[derive(Debug, Clone, Serialize)]
pub struct AlertPayload {
    pub event: String,
    pub tool_name: String,
    pub status: String,
    pub timestamp: String,
    pub policy_match: Option<String>,
    pub details: Option<String>,
}

/// Webhook manager for sending alerts
pub struct WebhookManager {
    configs: Vec<WebhookConfig>,
    client: reqwest::Client,
    tx: mpsc::Sender<AlertPayload>,
}

impl WebhookManager {
    /// Create a new webhook manager
    pub fn new(configs: Vec<WebhookConfig>) -> (Self, mpsc::Receiver<AlertPayload>) {
        let (tx, rx) = mpsc::channel(100);
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        let enabled_count = configs.iter().filter(|c| c.enabled).count();
        info!(
            "Webhook manager initialized with {} enabled webhooks",
            enabled_count
        );

        (
            Self {
                configs,
                client,
                tx,
            },
            rx,
        )
    }

    /// Get a sender handle for queueing alerts
    pub fn sender(&self) -> mpsc::Sender<AlertPayload> {
        self.tx.clone()
    }

    /// Start the webhook dispatcher loop
    pub async fn run(self, mut rx: mpsc::Receiver<AlertPayload>) {
        info!("Starting webhook dispatcher");

        while let Some(alert) = rx.recv().await {
            for config in &self.configs {
                if !config.enabled {
                    continue;
                }

                // Check filters
                if !config.event_filter.is_empty() && !config.event_filter.contains(&alert.event) {
                    continue;
                }

                if !config.status_filter.is_empty() && !config.status_filter.contains(&alert.status)
                {
                    continue;
                }

                // Send webhook
                if let Err(e) = self.send_webhook(config, &alert).await {
                    error!("Failed to send webhook to {}: {}", config.url, e);
                }
            }
        }
    }

    /// Send a webhook to a specific endpoint
    async fn send_webhook(
        &self,
        config: &WebhookConfig,
        alert: &AlertPayload,
    ) -> anyhow::Result<()> {
        let body = match config.webhook_type {
            WebhookType::Slack => self.format_slack(alert),
            WebhookType::Discord => self.format_discord(alert),
            WebhookType::Generic => serde_json::to_value(alert)?,
        };

        let response = self.client.post(&config.url).json(&body).send().await?;

        if response.status().is_success() {
            info!("Webhook sent successfully to {}", config.url);
        } else {
            warn!(
                "Webhook to {} returned status {}: {}",
                config.url,
                response.status(),
                response.text().await.unwrap_or_default()
            );
        }

        Ok(())
    }

    /// Format alert for Slack webhook
    fn format_slack(&self, alert: &AlertPayload) -> serde_json::Value {
        let color = if alert.status == "DENIED" {
            "danger"
        } else {
            "good"
        };
        let icon = if alert.status == "DENIED" {
            ":no_entry:"
        } else {
            ":white_check_mark:"
        };

        serde_json::json!({
            "attachments": [{
                "color": color,
                "title": format!("{} zn Security Alert", icon),
                "fields": [
                    { "title": "Event", "value": &alert.event, "short": true },
                    { "title": "Status", "value": &alert.status, "short": true },
                    { "title": "Tool", "value": &alert.tool_name, "short": true },
                    { "title": "Policy", "value": alert.policy_match.as_deref().unwrap_or("N/A"), "short": true },
                ],
                "footer": "zn Security Proxy",
                "ts": chrono::Utc::now().timestamp()
            }]
        })
    }

    /// Format alert for Discord webhook
    fn format_discord(&self, alert: &AlertPayload) -> serde_json::Value {
        let color = if alert.status == "DENIED" {
            0xFF0000
        } else {
            0x00FF00
        };
        let icon = if alert.status == "DENIED" {
            ":no_entry:"
        } else {
            ":white_check_mark:"
        };

        serde_json::json!({
            "embeds": [{
                "title": format!("{} zn Security Alert", icon),
                "color": color,
                "fields": [
                    { "name": "Event", "value": &alert.event, "inline": true },
                    { "name": "Status", "value": &alert.status, "inline": true },
                    { "name": "Tool", "value": &alert.tool_name, "inline": true },
                    { "name": "Policy", "value": alert.policy_match.as_deref().unwrap_or("N/A"), "inline": true },
                ],
                "footer": { "text": "zn Security Proxy" },
                "timestamp": &alert.timestamp
            }]
        })
    }
}

/// Send an alert without blocking
pub async fn send_alert(tx: &mpsc::Sender<AlertPayload>, alert: AlertPayload) {
    if tx.send(alert).await.is_err() {
        warn!("Failed to queue webhook alert - channel full or closed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_webhook_config_defaults() {
        let json = r#"{"url": "https://example.com/webhook"}"#;
        let config: WebhookConfig = serde_json::from_str(json).unwrap();

        assert_eq!(config.webhook_type, WebhookType::Generic);
        assert!(config.enabled);
        assert!(config.event_filter.is_empty());
    }

    #[test]
    fn test_alert_payload_serialization() {
        let alert = AlertPayload {
            event: "TOOL_CALL".to_string(),
            tool_name: "dangerous_tool".to_string(),
            status: "DENIED".to_string(),
            timestamp: "2024-01-15T10:00:00Z".to_string(),
            policy_match: Some("default_security".to_string()),
            details: None,
        };

        let json = serde_json::to_string(&alert).unwrap();
        assert!(json.contains("DENIED"));
        assert!(json.contains("dangerous_tool"));
    }
}
