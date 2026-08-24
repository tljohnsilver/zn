//! Policy Watcher Module
//!
//! Monitors the policy directory for changes and triggers reloads
//! in the ZnEngine automatically.

use crate::engine::ZnEngine;
use crossbeam_channel::{unbounded, Receiver};
use notify::{Config, Event, RecursiveMode, Watcher};
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{error, info};

pub struct PolicyWatcher {
    #[allow(dead_code)]
    watcher: notify::RecommendedWatcher,
    engine: Arc<ZnEngine>,
    #[allow(dead_code)]
    policy_dir: PathBuf,
}

impl PolicyWatcher {
    /// Create a new PolicyWatcher
    pub fn new(engine: Arc<ZnEngine>, policy_dir: impl Into<PathBuf>) -> anyhow::Result<Self> {
        let policy_dir = policy_dir.into();
        let (tx, rx) = unbounded();

        let mut watcher = notify::RecommendedWatcher::new(
            move |res| {
                if let Ok(event) = res {
                    let _ = tx.send(event);
                }
            },
            Config::default(),
        )?;

        watcher.watch(&policy_dir, RecursiveMode::NonRecursive)?;

        let watcher_instance = Self {
            watcher,
            engine,
            policy_dir,
        };

        // Spawn the event handler loop
        watcher_instance.spawn_handler(rx);

        Ok(watcher_instance)
    }

    fn spawn_handler(&self, rx: Receiver<Event>) {
        let engine = Arc::clone(&self.engine);

        tokio::spawn(async move {
            info!("Policy watcher started. Monitoring for changes...");

            while let Ok(event) = rx.recv() {
                if event.kind.is_modify() || event.kind.is_create() {
                    for path in event.paths {
                        if path.extension().is_some_and(|ext| ext == "wasm") {
                            info!("Policy change detected: {:?}", path);
                            // Give some time for the file to be fully written
                            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

                            if let Err(e) = engine.register_policy_from_file(&path) {
                                error!("Failed to reload policy {:?}: {}", path, e);
                            } else {
                                info!("Policy successfully reloaded: {:?}", path);
                            }
                        }
                    }
                } else if event.kind.is_remove() {
                    for path in event.paths {
                        if let Some(name) = path.file_stem().and_then(|s| s.to_str()) {
                            engine.unregister_policy(name);
                        }
                    }
                }
            }
        });
    }
}
