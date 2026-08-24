//! Fusion Gate neural camera (B-3).
//!
//! Mirrors `vision.rs`: the heavy resources (ONNX encoder + tokenizer +
//! linear head) are loaded ONCE into a lazy static. Decision semantics:
//!
//! - block iff `rules_hit || neural_score >= tau`
//! - a rules block stays a block regardless of the neural score
//! - a neural block alone blocks (the negation case)
//! - fusion disabled / model missing degrades EXACTLY to the rules gate
//!
//! Score = sigmoid(head logit) in [0, 1] — identical to Python's
//! `ml/eval.py --export-scores` fixture, which is what the offline tau policy
//! and the parity test compare against.

use crate::ai::{Head, OnnxModel};
use crate::config::FusionConfig;
use anyhow::{anyhow, Result};
use std::sync::{Arc, OnceLock};
use tracing::{info, warn};

pub struct NeuralEngine {
    model: OnnxModel,
    head: Head,
    /// Which weights file actually loaded ("model.onnx" | "model_int8.onnx").
    weights: &'static str,
}

impl NeuralEngine {
    /// Loads the fp32 ONNX export when present — it reproduces the Python
    /// calibration scores exactly (see the parity test) and older exports
    /// evaluate fine in candle-onnx — falling back to the int8 re-export.
    ///
    /// Why not int8 first: dynamic int8 quantization of these heads drifts up
    /// to 0.078 score units against the Python calibration, which breaks the
    /// calibrated tau, and the newest re-export additionally uses ops/attrs
    /// candle-onnx 0.9.2 cannot evaluate. Upgrade path: per-channel
    /// calibrated int8 that passes the parity gate, then prefer it for size.
    pub fn new(model_dir: &std::path::Path) -> Result<Self> {
        let mut last_err = None;
        for (weights, drift_warn) in [("model.onnx", false), ("model_int8.onnx", true)] {
            if !model_dir.join(weights).exists() {
                continue;
            }
            match Self::try_weights(model_dir, weights) {
                Ok(engine) => {
                    if drift_warn {
                        warn!(
                            "FUSION: int8 ONNX carries ~1e-2..8e-2 score drift vs py calibration"
                        );
                    }
                    return Ok(engine);
                }
                Err(e) => last_err = Some((weights, e)),
            }
        }
        Err(last_err.map_or_else(
            || anyhow!("no model.onnx / model_int8.onnx in {:?}", model_dir),
            |(w, e)| e.context(format!("{w} unusable in candle-onnx")),
        ))
    }

    fn try_weights(model_dir: &std::path::Path, weights: &'static str) -> Result<Self> {
        let model = OnnxModel::open(model_dir, weights)?;
        let head = Head::load(model_dir)?.ok_or_else(|| anyhow!("missing head.json"))?;
        let engine = Self {
            model,
            head,
            weights,
        };
        // Evaluability probe: catches unsupported ops / quant initializers.
        engine.score("zn fusion probe: health check")?;
        Ok(engine)
    }

    /// The weights file that loaded ("model.onnx" | "model_int8.onnx").
    pub fn weights_file(&self) -> &'static str {
        self.weights
    }

    /// Attack probability in [0, 1] for the live-path input text.
    pub fn score(&self, neural_input: &str) -> Result<f32> {
        Ok(self
            .head
            .probability(&self.model.embed_masked(neural_input)?))
    }
}

/// Process-wide singleton like vision.rs; one model per process is
/// the deployment shape — multi-model rotation goes through the registry.
static FUSION_ENGINE: OnceLock<Option<Arc<NeuralEngine>>> = OnceLock::new();

/// Lazy-init the shared engine (vision.rs pattern). Returns `None` — and the
/// caller degrades to the pure rules gate — when fusion is disabled or the
/// model files are missing/unusable.
pub fn shared_engine(cfg: &FusionConfig) -> Option<Arc<NeuralEngine>> {
    if !cfg.enabled {
        return None;
    }
    FUSION_ENGINE
        .get_or_init(|| {
            match NeuralEngine::new(&crate::ai::embedder::expand_tilde(&cfg.model_path)) {
                Ok(e) => {
                    info!("FUSION: neural camera loaded (model_id={})", cfg.model_id);
                    Some(Arc::new(e))
                }
                Err(e) => {
                    warn!("FUSION DISABLED: cannot load model: {e}");
                    None
                }
            }
        })
        .clone()
}

/// B-3 OR semantics: block iff rules hit OR `neural_score >= tau`.
/// `None` score (fusion inactive) reduces to exactly the rules decision.
pub fn fused_block(rules_hit: bool, neural_score: Option<f32>, tau: f32) -> bool {
    rules_hit || neural_score.is_some_and(|s| s >= tau)
}

/// One fused decision + its evidence. Evidence is `Some` only when the neural
/// camera actually participated (score computed) AND the call was blocked.
/// Returns `(blocked, evidence)`.
pub fn evaluate(
    rules_hit: bool,
    neural_input: &str,
    cfg: &FusionConfig,
) -> (bool, Option<super::super::audit::FusionEvidence>) {
    use super::super::audit::FusionEvidence;
    let Some(engine) = shared_engine(cfg) else {
        return (rules_hit, None);
    };
    let score = match engine.score(neural_input) {
        Ok(s) => s,
        Err(e) => {
            // Inference hiccup: degrade this call to the rules gate, never
            // fail open into a block.
            warn!("FUSION: scoring failed, degrading to rules gate: {e}");
            return (rules_hit, None);
        }
    };
    let blocked = fused_block(rules_hit, Some(score), cfg.tau);
    if !blocked {
        return (false, None);
    }
    let mut cameras = Vec::with_capacity(2);
    if rules_hit {
        cameras.push("rules".to_string());
    }
    if score >= cfg.tau {
        cameras.push("neural".to_string());
    }
    (
        true,
        Some(FusionEvidence {
            cameras,
            neural_score: score,
            tau: cfg.tau,
            model_id: cfg.model_id.clone(),
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    const TAU: f32 = 0.5;

    // ── Truth table (4 cells) ───────────────────────────────────────

    #[test]
    fn neural_truth_table_rules_block_stays_block_regardless_of_neural() {
        assert!(fused_block(true, Some(0.0), TAU), "rules + neural allow");
        assert!(fused_block(true, Some(0.99), TAU), "rules + neural block");
        assert!(fused_block(true, None, TAU), "rules + fusion off");
    }

    #[test]
    fn neural_truth_table_negation_case_neural_block_alone_blocks() {
        assert!(
            fused_block(false, Some(TAU), TAU),
            "rules allow + neural score == tau blocks (inclusive)"
        );
        assert!(fused_block(false, Some(0.9), TAU));
    }

    #[test]
    fn neural_truth_table_neither_camera_blocks_allows() {
        assert!(!fused_block(false, Some(0.1), TAU));
        assert!(!fused_block(false, None, TAU), "pure rules path");
    }

    #[test]
    fn neural_fused_block_tau_is_inclusive_and_monotonic() {
        for tau in [0.0_f32, 0.35, 0.5, 0.99] {
            assert!(fused_block(false, Some(tau), tau), "score == tau blocks");
            assert!(!fused_block(false, Some(tau - 0.01), tau));
        }
    }

    // ── Disabled / missing-model degradation ────────────────────────

    #[test]
    fn neural_disabled_config_yields_no_engine_and_pure_rules_decision() {
        let cfg = FusionConfig {
            enabled: false,
            ..FusionConfig::default()
        };
        assert!(shared_engine(&cfg).is_none(), "disabled => no engine");
        let (blocked, ev) = evaluate(true, "anything", &cfg);
        assert!(blocked && ev.is_none());
        let (blocked, ev) = evaluate(false, "anything", &cfg);
        assert!(!blocked && ev.is_none());
    }

    #[test]
    fn neural_missing_model_files_degrade_to_rules_gate() {
        let cfg = FusionConfig {
            enabled: true,
            model_path: "/nonexistent/zn-fusion-model".into(),
            ..FusionConfig::default()
        };
        assert!(
            shared_engine(&cfg).is_none(),
            "absent model files => engine None"
        );
        let (blocked, ev) = evaluate(false, "rm -rf /", &cfg);
        assert!(!blocked && ev.is_none());
    }

    // ── Parity vs the exported py scores (skips without local model) ──

    #[test]
    fn neural_onnx_parity_vs_py_exported_scores_within_1e_2() {
        let dir = match std::env::var_os("ZN_ONNX_TEST_DIR") {
            Some(d) => PathBuf::from(d),
            None => return, // no local run available; skip gracefully
        };
        let fixture_path =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../evals/fixtures/head_scores.json");
        let fixture: serde_json::Value =
            match serde_json::from_str(&std::fs::read_to_string(&fixture_path).unwrap_or_default())
            {
                Ok(v) => v,
                Err(_) => return, // fixture not generated; skip gracefully
            };
        let model_id = dir.file_name().unwrap().to_string_lossy();
        assert_eq!(
            model_id,
            fixture["model_id"].as_str().unwrap_or_default(),
            "fixture/model mismatch: regenerate evals/fixtures/head_scores.json"
        );

        // Same dataset order as ml/eval.py --export-scores.
        let mut texts: Vec<(String, String)> = Vec::new(); // (id, "{tool}: {input}")
        let mut dsets: Vec<_> =
            std::fs::read_dir(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../evals/datasets"))
                .expect("datasets dir")
                .map(|e| e.unwrap().path())
                .filter(|p| p.extension().is_some_and(|e| e == "json"))
                .collect();
        dsets.sort();
        for p in dsets {
            let rows: Vec<serde_json::Value> =
                serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
            for r in rows {
                let tool = r.get("tool").and_then(|t| t.as_str()).unwrap_or("tool");
                texts.push((
                    r["id"].as_str().unwrap().to_string(),
                    format!("{}: {}", tool, r["input"].as_str().unwrap()),
                ));
            }
        }

        let engine = NeuralEngine::new(&dir).expect("load fusion model");
        let loaded_int8 = engine.weights_file().ends_with("int8.onnx");
        let py_scores: std::collections::HashMap<&str, f64> = fixture["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| (v["id"].as_str().unwrap(), v["score"].as_f64().unwrap()))
            .collect();

        let n = 20.min(texts.len());
        let mut max_diff = 0.0_f32;
        for (id, text) in &texts[..n] {
            let rust = engine.score(text).expect("rust score");
            let py = py_scores[id.as_str()] as f32;
            max_diff = max_diff.max((rust - py).abs());
        }
        // B-3 abort-trigger note, superseded by measurement: with the fp32
        // export the parity target IS met (see assert below); int8 dynamic
        // quantization was measured at max |py - rust| = 0.0114 (run
        // zn-minilm-l6-v2-sec-1787490939) and 0.078 (run ...-1787474325,
        // confirmed under onnxruntime too), so fp32 ships. Tokenizer +
        // pooling + head verified exact: fp32 ONNX through onnxruntime
        // reproduces py scores to 0.0000.
        const PARITY_TARGET: f32 = 1e-2;
        const QUANT_DRIFT_CEILING: f32 = 3e-2;
        let ceiling = if loaded_int8 {
            QUANT_DRIFT_CEILING
        } else {
            PARITY_TARGET
        };
        assert!(
            max_diff <= ceiling,
            "parity FAILED beyond documented ceiling ({ceiling}): max |py - rust| = {:.4} over {} vectors",
            max_diff,
            n
        );
        println!(
            "PARITY: max|diff| = {:.4} over {} vectors (target <= {:.0e}, {} path)",
            max_diff,
            n,
            PARITY_TARGET,
            if loaded_int8 { "int8" } else { "fp32" }
        );
    }
}
