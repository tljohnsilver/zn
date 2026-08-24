//! MCP (Model Context Protocol) Server Pool Module
//!
//! Manages connections to MCP servers with:
//! - Auto-discovery of MCP configurations
//! - Connection pooling and health checks
//! - Support for Stdio and WebSocket transports
//! - Command validation for security
//! - Race-condition-free connection management

use anyhow::{anyhow, Result};
use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::process::{Child, Command};
use tokio::sync::Mutex;
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};
use tracing::{error, info, warn};

/// Configuration for an MCP server
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct McpServerConfig {
    /// Command to execute (for stdio transport)
    pub command: Option<String>,
    /// Command line arguments
    #[serde(default)]
    pub args: Vec<String>,
    /// Environment variables
    #[serde(default)]
    pub env: HashMap<String, String>,
    /// URL for WebSocket transport
    pub url: Option<String>,
}

/// Whitelist of allowed commands for MCP servers (security measure)
const ALLOWED_COMMANDS: &[&str] = &[
    "node", "npx", "python", "python3", "uvx", "uv", "cargo", "deno", "bun",
];

/// Validate that a command is in the allowed list
fn validate_command(command: &str) -> Result<()> {
    let cmd_name = Path::new(command)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(command);

    // Check against allowed commands (case-insensitive on Windows)
    let cmd_lower = cmd_name.to_lowercase();
    let cmd_base = cmd_lower.trim_end_matches(".exe").trim_end_matches(".cmd");

    if ALLOWED_COMMANDS.contains(&cmd_base) {
        Ok(())
    } else {
        warn!("Blocked MCP command not in whitelist: {}", command);
        Err(anyhow!(
            "Command '{}' is not in the allowed list. Allowed: {:?}",
            command,
            ALLOWED_COMMANDS
        ))
    }
}

/// A connection to an MCP server (stdio or websocket)
#[allow(clippy::large_enum_variant)]
pub enum McpConnection {
    Stdio {
        name: String,
        child: Child,
        stdin: BufWriter<tokio::process::ChildStdin>,
        stdout: BufReader<tokio::process::ChildStdout>,
    },
    WebSocket {
        name: String,
        url: String,
        ws_stream: Box<
            tokio_tungstenite::WebSocketStream<
                tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
            >,
        >,
    },
}

impl McpConnection {
    /// Connect to an MCP server based on config
    pub async fn connect(name: &str, config: &McpServerConfig) -> Result<Self> {
        if let Some(url) = &config.url {
            let mut attempts = 0;
            let max_attempts = 5;
            let mut delay = std::time::Duration::from_millis(500);

            loop {
                attempts += 1;
                info!(mcp = %name, url = %url, attempt = attempts, "Connecting to MCP via WebSocket");

                match connect_async(url).await {
                    Ok((ws_stream, _)) => {
                        return Ok(Self::WebSocket {
                            name: name.to_string(),
                            url: url.clone(),
                            ws_stream: Box::new(ws_stream),
                        });
                    }
                    Err(e) => {
                        if attempts >= max_attempts {
                            error!(mcp = %name, "Failed to connect after {} attempts: {}", max_attempts, e);
                            return Err(anyhow!("Failed to connect to WS MCP '{}': {}", name, e));
                        }
                        warn!(mcp = %name, "Connection failed: {}. Retrying in {:?}...", e, delay);
                        tokio::time::sleep(delay).await;
                        delay *= 2;
                    }
                }
            }
        } else if let Some(command) = &config.command {
            // Validate command before spawning
            validate_command(command)?;

            info!(mcp = %name, command = %command, "Spawning MCP server");

            let mut cmd = Command::new(command);
            cmd.args(&config.args)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::inherit())
                .kill_on_drop(true);

            // Validate and apply environment variables
            for (key, value) in &config.env {
                if Self::is_safe_env_var(key) {
                    cmd.env(key, value);
                } else {
                    warn!("Skipping potentially dangerous env var: {}", key);
                }
            }

            let mut child = cmd
                .spawn()
                .map_err(|e| anyhow!("Failed to spawn MCP '{}': {}", name, e))?;

            let stdin = child
                .stdin
                .take()
                .ok_or_else(|| anyhow!("Failed to capture stdin"))?;
            let stdout = child
                .stdout
                .take()
                .ok_or_else(|| anyhow!("Failed to capture stdout"))?;

            Ok(Self::Stdio {
                name: name.to_string(),
                child,
                stdin: BufWriter::new(stdin),
                stdout: BufReader::new(stdout),
            })
        } else {
            Err(anyhow!(
                "MCP config for '{}' must have either 'command' or 'url'",
                name
            ))
        }
    }

    /// Send a request to the MCP server and wait for response
    pub async fn send_request(&mut self, request: &str) -> Result<String> {
        match self {
            Self::Stdio { stdin, stdout, .. } => {
                stdin.write_all(request.as_bytes()).await?;
                stdin.write_all(b"\n").await?;
                stdin.flush().await?;

                let mut response = String::new();
                stdout.read_line(&mut response).await?;
                Ok(response.trim().to_string())
            }
            Self::WebSocket { ws_stream, .. } => {
                ws_stream
                    .send(Message::Text(request.to_string().into()))
                    .await?;

                while let Some(msg) = ws_stream.next().await {
                    match msg? {
                        Message::Text(text) => return Ok(text.to_string()),
                        _ => continue,
                    }
                }
                Err(anyhow!("WebSocket closed without response"))
            }
        }
    }

    /// Check if the MCP connection is still alive
    pub fn is_alive(&mut self) -> bool {
        match self {
            Self::Stdio { child, .. } => matches!(child.try_wait(), Ok(None)),
            Self::WebSocket { .. } => true, // TODO: Better health check for WS
        }
    }

    /// Gracefully shutdown the MCP connection
    pub async fn shutdown(&mut self) -> Result<()> {
        match self {
            Self::Stdio { name, child, .. } => {
                info!(mcp = %name, "Killing MCP process");
                let _ = child.kill().await;
            }
            Self::WebSocket {
                name, ws_stream, ..
            } => {
                info!(mcp = %name, "Closing MCP WebSocket");
                let _ = (*ws_stream).close().await;
            }
        }
        Ok(())
    }

    fn is_safe_env_var(name: &str) -> bool {
        const BLOCKED_ENV_VARS: &[&str] = &[
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
            "DYLD_INSERT_LIBRARIES",
            "DYLD_LIBRARY_PATH",
            "PATH",
            "HOME",
            "USERPROFILE",
            "SHELL",
            "COMSPEC",
        ];
        let name_upper = name.to_uppercase();
        !BLOCKED_ENV_VARS
            .iter()
            .any(|&blocked| blocked == name_upper)
    }
}

/// Pool of MCP server connections
pub struct McpPool {
    /// Server configurations
    configs: HashMap<String, McpServerConfig>,
    /// Active connections
    connections: Mutex<HashMap<String, McpConnection>>,
    /// Optional Result Cache
    cache: Option<Arc<crate::engine::cache::ResultCache>>,
}

impl McpPool {
    /// Create a new MCP pool with the given configurations
    pub fn new(configs: HashMap<String, McpServerConfig>) -> Self {
        Self {
            configs,
            connections: Mutex::new(HashMap::new()),
            cache: None,
        }
    }

    /// Set the result cache for the pool
    pub fn with_cache(mut self, cache: Arc<crate::engine::cache::ResultCache>) -> Self {
        self.cache = Some(cache);
        self
    }

    /// Auto-discover MCP configurations from standard locations
    pub fn auto_discover() -> Result<Self> {
        let home = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE"))?;

        // Only search in user-controlled directories
        let search_paths = [
            format!("{}/.claude/mcp_servers.json", home),
            format!("{}/.config/claude/mcp_servers.json", home),
        ];

        for path in &search_paths {
            let path_obj = Path::new(path);
            if path_obj.exists() {
                info!("Found MCP config at: {}", path);
                match Self::from_config_file(path) {
                    Ok(pool) => return Ok(pool),
                    Err(e) => {
                        warn!("Failed to load MCP config from {}: {}", path, e);
                        continue;
                    }
                }
            }
        }

        info!("No MCP configuration found, using empty pool");
        Ok(Self::new(HashMap::new()))
    }

    /// Load MCP configurations from a JSON file
    fn from_config_file(path: &str) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| anyhow!("Failed to read MCP config file '{}': {}", path, e))?;

        let value: serde_json::Value = serde_json::from_str(&content)
            .map_err(|e| anyhow!("Failed to parse MCP config file '{}': {}", path, e))?;

        let mut configs = HashMap::new();

        if let Some(servers) = value.get("mcpServers").and_then(|v| v.as_object()) {
            for (name, server) in servers {
                let command = server
                    .get("command")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let url = server
                    .get("url")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                if command.is_none() && url.is_none() {
                    warn!(
                        "Skipping MCP server '{}': missing both 'command' and 'url'",
                        name
                    );
                    continue;
                }

                if let Some(ref cmd) = command {
                    if let Err(e) = validate_command(cmd) {
                        warn!("Skipping MCP server '{}': {}", name, e);
                        continue;
                    }
                }

                let args = server
                    .get("args")
                    .and_then(|v| v.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                    .unwrap_or_default();

                let env = server
                    .get("env")
                    .and_then(|v| v.as_object())
                    .map(|o| {
                        o.iter()
                            .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                            .collect()
                    })
                    .unwrap_or_default();

                configs.insert(
                    name.clone(),
                    McpServerConfig {
                        command,
                        args,
                        env,
                        url,
                    },
                );
                info!("Loaded MCP server config: {}", name);
            }
        }

        Ok(Self::new(configs))
    }

    /// Send a request to an MCP server, connecting if necessary.
    /// Supports caching if enabled.
    pub async fn send(&self, name: &str, request: &str, agent_id: Option<&str>) -> Result<String> {
        // 1. Try Cache if it's a tool call
        // (Simplification: We assume the caller manages cache lookup for requests,
        // but we handle STORING the response here).

        let config = self
            .configs
            .get(name)
            .ok_or_else(|| anyhow!("Unknown MCP server: {}", name))?
            .clone();

        let mut connections = self.connections.lock().await;

        let conn = match connections.entry(name.to_string()) {
            Entry::Occupied(mut entry) => {
                if !entry.get_mut().is_alive() {
                    info!("MCP '{}' connection died, reconnecting", name);
                    let new_conn = McpConnection::connect(name, &config).await?;
                    entry.insert(new_conn);
                }
                entry.into_mut()
            }
            Entry::Vacant(entry) => {
                info!("Establishing new MCP connection: {}", name);
                let conn = McpConnection::connect(name, &config).await?;
                entry.insert(conn)
            }
        };

        let response = conn.send_request(request).await?;

        // 2. Store in cache if successful and it looks like a tool call
        if let Some(ref cache) = self.cache {
            if let Some(agent) = agent_id {
                // We only cache successful non-empty JSON responses
                if !response.is_empty() && response.contains("\"result\"") {
                    // We need the tool name and args to cache properly.
                    // This is a bit tricky here as we only have the raw request string.
                    // For now, we'll use a simpler hash-based key if we can't parse it perfectly.
                    cache.set(agent, name, request, response.clone());
                }
            }
        }

        Ok(response)
    }

    /// Get a list of configured MCP server names
    pub fn list_mcps(&self) -> Vec<String> {
        self.configs.keys().cloned().collect()
    }

    /// Check the health of all MCP connections
    pub async fn health_check(&self) -> HashMap<String, bool> {
        let mut connections = self.connections.lock().await;
        let mut status = HashMap::new();

        for (name, conn) in connections.iter_mut() {
            status.insert(name.clone(), conn.is_alive());
        }

        for name in self.configs.keys() {
            status.entry(name.clone()).or_insert(false);
        }

        status
    }

    /// Shutdown all MCP connections gracefully
    pub async fn shutdown_all(&self) {
        let mut connections = self.connections.lock().await;
        for (name, mut conn) in connections.drain() {
            info!("Shutting down MCP: {}", name);
            let _ = conn.shutdown().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_command_allowed() {
        assert!(validate_command("node").is_ok());
        assert!(validate_command("python").is_ok());
        assert!(validate_command("npx").is_ok());
    }

    #[test]
    fn test_validate_command_blocked() {
        assert!(validate_command("bash").is_err());
        assert!(validate_command("rm").is_err());
    }
}
