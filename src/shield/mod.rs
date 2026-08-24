use serde::{Deserialize, Serialize};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

#[derive(Debug, Serialize, Deserialize)]
pub struct ScanResult {
    pub port: u16,
    pub is_open: bool,
    pub service: String,
    pub vulnerable: bool,
}

pub struct McpShield;

impl McpShield {
    /// Scan for common MCP ports exposed on 0.0.0.0
    pub fn scan_local_exposure() -> Vec<ScanResult> {
        let common_ports = [3000, 8000, 8080, 9090, 50051];
        let mut results = Vec::new();

        for port in common_ports {
            let addr = format!("0.0.0.0:{}", port);
            let socket_addr: SocketAddr = addr.parse().unwrap();

            let is_open =
                TcpStream::connect_timeout(&socket_addr, Duration::from_millis(50)).is_ok();

            if is_open {
                results.push(ScanResult {
                    port,
                    is_open: true,
                    service: "Potential MCP/Web".to_string(),
                    vulnerable: true,
                });
            }
        }
        results
    }

    /// Check if a WebSocket origin is allowed
    pub fn validate_origin(origin: &str, allowed_origins: &[String]) -> bool {
        if allowed_origins.is_empty() {
            // Default to only localhost
            return origin.contains("localhost") || origin.contains("127.0.0.1");
        }
        allowed_origins.iter().any(|o| origin == o)
    }

    /// Generate an ephemeral auth token for WS
    pub fn generate_ws_token() -> String {
        uuid::Uuid::new_v4().to_string()
    }
}

pub mod canary {

    /// Detect potential Shodan scans based on specific JSON-RPC patterns
    pub fn is_shodan_probe(payload: &str) -> bool {
        // Shodan often uses these patterns to identify MCP servers
        payload.contains("\"method\":\"initialize\"") && payload.contains("\"jsonrpc\":\"2.0\"")
    }
}
