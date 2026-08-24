//! Canary deployment for model backends: hot-swap via `Mutex<Arc<dyn>>`
//! (sub-µs lock; negligible vs the ~4 ms embed), per-agent rollout
//! percentage (stable hash), FPR guard with auto-rollback, and an evals
//! gate before promotion.
//!
//! The decision loop feeds one `note` per call; the pure `should_rollback`
//! logic is unit-tested here. Live audit wiring lands in E-2.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex};

/// Decision counters feeding the FPR guard.
/// FP = neural flagged but the rule layers allowed it; TN = not flagged & allowed.
#[derive(Debug, Default, Clone, Copy)]
pub struct CanaryStats {
    pub canary_total: u64,
    pub control_total: u64,
    pub canary_fp: u64,
    pub control_fp: u64,
    pub canary_tn: u64,
    pub control_tn: u64,
}

impl CanaryStats {
    /// `bucket` = served by the canary, `flagged` = neural fired, `allowed` = allowed at the end.
    pub fn note(&mut self, bucket: bool, flagged: bool, allowed: bool) {
        if bucket {
            self.canary_total += 1;
        } else {
            self.control_total += 1;
        }
        if allowed {
            if flagged {
                if bucket {
                    self.canary_fp += 1;
                } else {
                    self.control_fp += 1;
                }
            } else if bucket {
                self.canary_tn += 1;
            } else {
                self.control_tn += 1;
            }
        }
    }

    pub fn canary_fpr(&self) -> f64 {
        fpr_of(self.canary_fp, self.canary_tn)
    }

    pub fn control_fpr(&self) -> f64 {
        fpr_of(self.control_fp, self.control_tn)
    }

    /// Rollback rule: enough canary samples AND canary FPR above control FPR + margin.
    pub fn should_rollback(&self, min_samples: u64, margin: f64) -> bool {
        if self.canary_total < min_samples {
            return false;
        }
        self.canary_fpr() > self.control_fpr() + margin
    }
}

fn fpr_of(fp: u64, tn: u64) -> f64 {
    let d = fp + tn;
    if d == 0 {
        return 0.0;
    }
    fp as f64 / d as f64
}

struct Canary {
    model: Arc<dyn super::ModelBackend>,
    pct: u8,
}

/// Hot-swappable model deployer. `current` is the always-healthy backend;
/// `canary` (when set) serves a stable % of agents.
pub struct CanaryDeployer {
    current: Mutex<Arc<dyn super::ModelBackend>>,
    canary: Mutex<Option<Canary>>,
    stats: Mutex<CanaryStats>,
}

impl CanaryDeployer {
    pub fn new(current: Arc<dyn super::ModelBackend>) -> Self {
        Self {
            current: Mutex::new(current),
            canary: Mutex::new(None),
            stats: Mutex::new(CanaryStats::default()),
        }
    }

    /// Record one decision for the agent's routed bucket.
    pub fn note(&self, agent_id: &str, flagged: bool, allowed: bool) {
        let bucket = self.is_canary_bucket(agent_id);
        self.stats.lock().unwrap().note(bucket, flagged, allowed);
    }

    pub fn stats(&self) -> CanaryStats {
        *self.stats.lock().unwrap()
    }

    /// FPR of the serving population: the canary while one is active (the
    /// population the FPR guard watches), otherwise the control bucket.
    pub fn serving_fpr(&self) -> f64 {
        let s = self.stats();
        if self.has_canary() {
            s.canary_fpr()
        } else {
            s.control_fpr()
        }
    }

    /// Roll back with the live stats. True if it rolled.
    pub fn enforce_guard(&self, min_samples: u64, margin: f64) -> bool {
        let s = self.stats();
        self.enforce_fpr_guard(&s, min_samples, margin)
    }

    /// Stable bucket in [0, 100). Same agent always lands in the same bucket.
    pub fn bucket(agent_id: &str) -> u8 {
        let mut h = DefaultHasher::new();
        agent_id.hash(&mut h);
        (h.finish() % 100) as u8
    }

    pub fn active(&self) -> Arc<dyn super::ModelBackend> {
        self.current.lock().unwrap().clone()
    }

    pub fn has_canary(&self) -> bool {
        self.canary.lock().unwrap().is_some()
    }

    /// Route one agent to the backend serving it (canary when in-bucket).
    pub fn backend_for(&self, agent_id: &str) -> Arc<dyn super::ModelBackend> {
        let c = {
            let g = self.canary.lock().unwrap();
            g.as_ref().and_then(|c| {
                if Self::bucket(agent_id) < c.pct {
                    Some(Arc::clone(&c.model))
                } else {
                    None
                }
            })
        };
        match c {
            Some(m) => m,
            None => self.current.lock().unwrap().clone(),
        }
    }

    /// True if `agent_id` is currently served by the canary (stats bucketing).
    pub fn is_canary_bucket(&self, agent_id: &str) -> bool {
        self.canary
            .lock()
            .unwrap()
            .as_ref()
            .map(|c| Self::bucket(agent_id) < c.pct)
            .unwrap_or(false)
    }

    /// Start (or replace) the canary with `pct` in 1..=100.
    pub fn set_canary(&self, model: Arc<dyn super::ModelBackend>, pct: u8) {
        let pct = pct.clamp(1, 100);
        *self.canary.lock().unwrap() = Some(Canary { model, pct });
    }

    /// Promote the canary to current (hot swap). Requires a passed evals gate.
    /// Returns false (canary untouched) if the gate did not pass.
    pub fn promote(&self, gate_passed: bool) -> bool {
        if !gate_passed {
            return false;
        }
        let canary = self.canary.lock().unwrap().take();
        match canary {
            Some(c) => {
                *self.current.lock().unwrap() = Arc::clone(&c.model);
                true
            }
            None => false,
        }
    }

    /// Drop the canary; `current` keeps serving everyone.
    pub fn rollback(&self) {
        *self.canary.lock().unwrap() = None;
    }

    /// Roll back automatically when the FPR guard trips. True if it rolled.
    pub fn enforce_fpr_guard(&self, stats: &CanaryStats, min_samples: u64, margin: f64) -> bool {
        if stats.should_rollback(min_samples, margin) {
            self.rollback();
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ai::ModelBackend;

    struct Stub {
        name: String,
    }
    impl ModelBackend for Stub {
        fn embed(&self, _t: &str) -> anyhow::Result<Vec<f32>> {
            Ok(vec![1.0])
        }
        fn classify(&self, _v: &[f32]) -> anyhow::Result<Option<f32>> {
            Ok(None)
        }
        fn name(&self) -> &str {
            &self.name
        }
        fn dim(&self) -> usize {
            1
        }
    }

    #[test]
    fn bucket_is_stable_and_in_range() {
        for agent in ["agent-1", "tenant:42:op", "x"] {
            let b1 = CanaryDeployer::bucket(agent);
            let b2 = CanaryDeployer::bucket(agent);
            assert_eq!(b1, b2, "bucket must be deterministic");
            assert!(b1 < 100);
        }
    }

    #[test]
    fn routing_respects_canary_pct() {
        let cur: Arc<dyn ModelBackend> = Arc::new(Stub { name: "cur".into() });
        let can: Arc<dyn ModelBackend> = Arc::new(Stub { name: "can".into() });
        let d = CanaryDeployer::new(Arc::clone(&cur));
        assert!(!d.has_canary());
        assert_eq!(d.backend_for("agent-1").name(), "cur");

        d.set_canary(Arc::clone(&can), 100);
        assert_eq!(d.backend_for("agent-1").name(), "can", "100% => everyone");

        d.rollback();
        assert!(!d.has_canary());
        assert_eq!(d.backend_for("agent-1").name(), "cur");

        d.set_canary(Arc::clone(&can), 1);
        // at 1%, routing must agree with the bucket function for every agent
        for i in 0..200u32 {
            let a = format!("agent-{i}");
            let expected = if CanaryDeployer::bucket(&a) < 1 {
                "can"
            } else {
                "cur"
            };
            assert_eq!(d.backend_for(&a).name(), expected);
        }
    }

    #[test]
    fn promote_requires_gate_and_hot_swaps() {
        let cur: Arc<dyn ModelBackend> = Arc::new(Stub { name: "cur".into() });
        let can: Arc<dyn ModelBackend> = Arc::new(Stub { name: "can".into() });
        let d = CanaryDeployer::new(cur);
        d.set_canary(Arc::clone(&can), 50);
        assert!(!d.promote(false), "no promotion without gate");
        assert!(d.has_canary());
        assert!(d.promote(true));
        assert!(!d.has_canary());
        assert_eq!(
            d.active().name(),
            "can",
            "hot-swap must install canary as current"
        );
    }

    #[test]
    fn fpr_guard_trips_rollback_only_when_worse() {
        let mut good = CanaryStats::default();
        for _ in 0..60 {
            good.note(true, false, true); // canary TNs
        }
        good.note(true, true, true); // 1 canary FP
        for _ in 0..60 {
            good.note(false, false, true); // control TNs
        }
        good.note(false, true, true); // 1 control FP (parity)
        assert!(!good.should_rollback(50, 0.02), "parity must not trip");
        assert!((good.canary_fpr() - 1.0 / 61.0).abs() < 1e-9);

        let mut bad = good;
        for _ in 0..15 {
            bad.note(true, true, true); // 15 more canary FPs
        }
        assert!(
            bad.should_rollback(50, 0.02),
            "canary FPR well above control must trip"
        );

        let mut starved = CanaryStats::default();
        starved.note(true, true, true);
        starved.note(true, true, true);
        assert!(
            !starved.should_rollback(50, 0.0),
            "no rollback without min samples"
        );
    }

    #[test]
    fn enforce_rolls_back_on_trip() {
        let cur: Arc<dyn ModelBackend> = Arc::new(Stub { name: "cur".into() });
        let can: Arc<dyn ModelBackend> = Arc::new(Stub { name: "can".into() });
        let d = CanaryDeployer::new(cur);
        d.set_canary(can, 10);
        let mut s = CanaryStats::default();
        for _ in 0..60 {
            s.note(true, false, true);
        }
        for _ in 0..60 {
            s.note(false, false, true);
        }
        for _ in 0..20 {
            s.note(true, true, true); // canary FPs
        }
        for _ in 0..5 {
            s.note(false, true, true); // fewer control FPs
        }
        assert!(d.enforce_fpr_guard(&s, 50, 0.02));
        assert!(!d.has_canary(), "rollback must drop the canary");
    }
}
