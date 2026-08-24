//! Model registry (SQLite via rusqlite): versions of models, status and metrics.
//! A row is the unit of promotion/rollback (Phase C-3) and audit (Phase E).

use anyhow::{Context, Result};
use rusqlite::{params, Connection};
use std::path::Path;

#[derive(Debug, Clone)]
pub struct ModelEntry {
    pub id: String,
    pub model_id: String,
    pub version: String,
    pub dim: i64,
    pub path: String,
    pub metrics: String, // JSON (train-time holdout)
    pub status: String,  // staging | active | canary | retired
    pub created_at: i64,
}

pub struct ModelRegistry {
    conn: Connection,
}

impl ModelRegistry {
    pub fn new(path: &str) -> Result<Self> {
        if let Some(parent) = Path::new(path).parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let conn = Connection::open(path).context("open model registry")?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS models (
                id INTEGER PRIMARY KEY,
                model_id TEXT NOT NULL,
                version TEXT NOT NULL,
                dim INTEGER NOT NULL,
                path TEXT NOT NULL,
                metrics TEXT NOT NULL DEFAULT '{}',
                status TEXT NOT NULL DEFAULT 'staging',
                created_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_models_status ON models(status);",
        )
        .context("migrate model registry")?;
        Ok(Self { conn })
    }

    /// Inserts and returns the entry with its generated id.
    pub fn register(&self, e: &ModelEntry) -> Result<ModelEntry> {
        let id = {
            let mut stmt = self
                .conn
                .prepare("INSERT INTO models (model_id, version, dim, path, metrics, status, created_at) VALUES (?1,?2,?3,?4,?5,?6,?7)")?;
            stmt.execute(params![
                e.model_id,
                e.version,
                e.dim,
                e.path,
                e.metrics,
                e.status,
                e.created_at
            ])?;
            self.conn.last_insert_rowid()
        };
        Ok(ModelEntry {
            id: id.to_string(),
            ..e.clone()
        })
    }

    pub fn get(&self, id: &str) -> Result<Option<ModelEntry>> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, model_id, version, dim, path, metrics, status, created_at FROM models WHERE id = ?1")?;
        let mut rows = stmt.query_map(params![id], |r| {
            Ok(ModelEntry {
                id: r.get::<_, i64>(0)?.to_string(),
                model_id: r.get(1)?,
                version: r.get(2)?,
                dim: r.get(3)?,
                path: r.get(4)?,
                metrics: r.get(5)?,
                status: r.get(6)?,
                created_at: r.get(7)?,
            })
        })?;
        match rows.next() {
            Some(r) => Ok(Some(r?)),
            None => Ok(None),
        }
    }

    pub fn entries(&self, status: Option<&str>) -> Result<Vec<ModelEntry>> {
        let q = "SELECT id, model_id, version, dim, path, metrics, status, created_at FROM models";
        let mut out = Vec::new();
        match status {
            Some(s) => {
                let mut stmt = self.conn.prepare(&format!("{q} WHERE status = ?1"))?;
                let rows = stmt.query_map(params![s], row_map)?;
                for r in rows {
                    out.push(r?);
                }
            }
            None => {
                let mut stmt = self.conn.prepare(q)?;
                let rows = stmt.query_map([], row_map)?;
                for r in rows {
                    out.push(r?);
                }
            }
        }
        out.sort_by_key(|e| std::cmp::Reverse(e.created_at));
        Ok(out)
    }

    pub fn set_status(&self, id: &str, status: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE models SET status = ?2 WHERE id = ?1",
            params![id, status],
        )?;
        Ok(())
    }
}

fn row_map(r: &rusqlite::Row) -> rusqlite::Result<ModelEntry> {
    Ok(ModelEntry {
        id: r.get::<_, i64>(0)?.to_string(),
        model_id: r.get(1)?,
        version: r.get(2)?,
        dim: r.get(3)?,
        path: r.get(4)?,
        metrics: r.get(5)?,
        status: r.get(6)?,
        created_at: r.get(7)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id_suffix: &str) -> ModelEntry {
        ModelEntry {
            id: String::new(),
            model_id: "zn-minilm".to_string(),
            version: format!("v-{id_suffix}"),
            dim: 384,
            path: format!("/models/{id_suffix}"),
            metrics: "{\"f1\":0.9}".to_string(),
            status: "staging".to_string(),
            created_at: 1_700_000_000 + id_suffix.chars().next().unwrap() as i64,
        }
    }

    #[test]
    fn register_get_and_status_lifecycle() {
        let dir = std::env::temp_dir().join(format!("zn-reg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("models.db").to_string_lossy().to_string();
        let reg = ModelRegistry::new(&db).unwrap();
        let a = reg.register(&entry("a")).unwrap();
        let b = reg.register(&entry("b")).unwrap();
        assert_ne!(a.id, b.id);
        assert_eq!(reg.get(&a.id).unwrap().unwrap().model_id, "zn-minilm");
        reg.set_status(&a.id, "canary").unwrap();
        assert_eq!(reg.get(&a.id).unwrap().unwrap().status, "canary");
        reg.set_status(&a.id, "active").unwrap();
        assert_eq!(reg.entries(Some("active")).unwrap().len(), 1);
        assert_eq!(reg.entries(None).unwrap().len(), 2);
        // newest first
        assert_eq!(reg.entries(None).unwrap()[0].id, b.id);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
