//! SIEM Exporter Module
//!
//! Handles exporting audit logs to external SIEM systems (e.g. Elastic, Splunk, Datadog)
//! via HTTP/JSON.

use crate::audit::AuditEntry;
use crate::config::SiemConfig;
use reqwest::Client;
use tokio::sync::broadcast;
use tracing::{error, info, warn};

pub struct SiemExporter {
    config: SiemConfig,
    client: Client,
}

impl SiemExporter {
    pub fn new(config: SiemConfig) -> Self {
        Self {
            config,
            client: Client::new(),
        }
    }

    /// Run the exporter loop
    pub async fn run(self, mut rx: broadcast::Receiver<AuditEntry>) {
        let endpoint = match &self.config.endpoint {
            Some(e) => e.clone(),
            None => {
                info!("SIEM exporter disabled (no endpoint configured)");
                return;
            }
        };

        info!("SIEM exporter active, sending to {}", endpoint);

        let mut batch = Vec::with_capacity(self.config.batch_size);

        loop {
            tokio::select! {
                result = rx.recv() => {
                    match result {
                        Ok(entry) => {
                            batch.push(entry);
                            if batch.len() >= self.config.batch_size {
                                self.send_batch(&endpoint, &mut batch).await;
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            warn!("SIEM exporter lagged behind: lost {} events", n);
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            info!("SIEM exporter stopping: channel closed");
                            break;
                        }
                    }
                }
                // Periodic flush every 5 seconds if batch is not empty
                _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => {
                    if !batch.is_empty() {
                        self.send_batch(&endpoint, &mut batch).await;
                    }
                }
            }
        }
    }

    async fn send_batch(&self, endpoint: &str, batch: &mut Vec<AuditEntry>) {
        let count = batch.len();
        info!("Sending batch of {} events to SIEM", count);

        let mut req = self.client.post(endpoint).json(batch);

        if let Some(token) = &self.config.token {
            req = req.header("Authorization", format!("Bearer {}", token));
        }

        match req.send().await {
            Ok(resp) if resp.status().is_success() => {
                batch.clear();
            }
            Ok(resp) => {
                error!(
                    "SIEM export failed: server returned status {}",
                    resp.status()
                );
                // In production, you might want a retry logic or local buffer
            }
            Err(e) => {
                error!("SIEM export network error: {}", e);
            }
        }
    }
}
