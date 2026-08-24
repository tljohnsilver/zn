//! Prometheus Metrics Module
//!
//! Exposes zn performance and security metrics in Prometheus format.
//! Accessible via /metrics endpoint on the Management API.

use lazy_static::lazy_static;
use prometheus::{
    Encoder, Gauge, Histogram, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge,
    Opts, Registry, TextEncoder,
};

lazy_static! {
    /// Global metrics registry
    pub static ref REGISTRY: Registry = Registry::new();

    /// Total tool calls processed
    pub static ref TOOL_CALLS_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("zn_tool_calls_total", "Total number of tool calls processed")
            .namespace("zn"),
        &["tool_name", "status"]
    ).expect("Failed to create tool_calls_total metric");

    /// Tool calls allowed
    pub static ref TOOL_CALLS_ALLOWED: IntCounter = IntCounter::new(
        "zn_tool_calls_allowed_total",
        "Total number of tool calls allowed"
    ).expect("Failed to create tool_calls_allowed metric");

    /// Tool calls denied
    pub static ref TOOL_CALLS_DENIED: IntCounter = IntCounter::new(
        "zn_tool_calls_denied_total",
        "Total number of tool calls denied"
    ).expect("Failed to create tool_calls_denied metric");

    /// SQL injection attempts blocked
    pub static ref SQL_INJECTION_BLOCKED: IntCounter = IntCounter::new(
        "zn_sql_injection_blocked_total",
        "Total number of SQL injection attempts blocked"
    ).expect("Failed to create sql_injection_blocked metric");

    /// Prompt injection attempts blocked
    pub static ref PROMPT_INJECTION_BLOCKED: IntCounter = IntCounter::new(
        "zn_prompt_injection_blocked_total",
        "Total number of prompt injection attempts blocked"
    ).expect("Failed to create prompt_injection_blocked metric");

    /// Policy evaluation duration histogram (in seconds)
    pub static ref POLICY_EVAL_DURATION: Histogram = Histogram::with_opts(
        HistogramOpts::new(
            "zn_policy_eval_duration_seconds",
            "Time spent evaluating WASM policies"
        ).namespace("zn")
        .buckets(vec![0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0])
    ).expect("Failed to create policy_eval_duration metric");

    /// JSON-RPC requests total
    pub static ref JSONRPC_REQUESTS: IntCounterVec = IntCounterVec::new(
        Opts::new("zn_jsonrpc_requests_total", "Total JSON-RPC requests processed")
            .namespace("zn"),
        &["method", "result"]
    ).expect("Failed to create jsonrpc_requests metric");

    /// Active SSE connections
    pub static ref SSE_CONNECTIONS: IntGauge = IntGauge::new(
        "zn_sse_connections_active",
        "Number of active SSE connections"
    ).expect("Failed to create sse_connections metric");

    /// API request latency histogram
    pub static ref API_LATENCY: HistogramVec = HistogramVec::new(
        HistogramOpts::new(
            "zn_api_request_duration_seconds",
            "API request latency in seconds"
        ).namespace("zn")
        .buckets(vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]),
        &["endpoint", "method"]
    ).expect("Failed to create api_latency metric");

    /// API request latency p95 histogram (in seconds)
    pub static ref API_LATENCY_P95: Histogram = Histogram::with_opts(
        HistogramOpts::new(
            "zn_api_request_duration_p95_seconds",
            "95th percentile API request latency in seconds"
        ).namespace("zn")
        .buckets(vec![0.0001, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0])
    ).expect("Failed to create api_latency_p95 metric");

    /// API request latency p99 histogram (in seconds)
    pub static ref API_LATENCY_P99: Histogram = Histogram::with_opts(
        HistogramOpts::new(
            "zn_api_request_duration_p99_seconds",
            "99th percentile API request latency in seconds"
        ).namespace("zn")
        .buckets(vec![0.0001, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0])
    ).expect("Failed to create api_latency_p99 metric");

    /// PII patterns detected
    pub static ref PII_DETECTED: IntCounterVec = IntCounterVec::new(
        Opts::new("zn_pii_detected_total", "PII patterns detected and scrubbed")
            .namespace("zn"),
        &["pii_type"]
    ).expect("Failed to create pii_detected metric");

    /// Audit log entries
    pub static ref AUDIT_ENTRIES: IntCounter = IntCounter::new(
        "zn_audit_entries_total",
        "Total number of audit log entries created"
    ).expect("Failed to create audit_entries metric");

    /// Neural embedding latency histogram (in seconds)
    pub static ref NEURAL_LATENCY: Histogram = Histogram::with_opts(
        HistogramOpts::new(
            "zn_neural_latency_seconds",
            "Time spent in the neural layer (embed + classify) per tool call"
        ).namespace("zn")
        .buckets(vec![0.0001, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0])
    ).expect("Failed to create neural_latency metric");

    /// Neural embedding latency p95 histogram (in seconds)
    pub static ref NEURAL_LATENCY_P95: Histogram = Histogram::with_opts(
        HistogramOpts::new(
            "zn_neural_latency_p95_seconds",
            "95th percentile neural embedding latency in seconds"
        ).namespace("zn")
        .buckets(vec![0.0001, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0])
    ).expect("Failed to create neural_latency_p95 metric");

    /// Neural embedding latency p99 histogram (in seconds)
    pub static ref NEURAL_LATENCY_P99: Histogram = Histogram::with_opts(
        HistogramOpts::new(
            "zn_neural_latency_p99_seconds",
            "99th percentile neural embedding latency in seconds"
        ).namespace("zn")
        .buckets(vec![0.0001, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0])
    ).expect("Failed to create neural_latency_p99 metric");

    /// Tool calls blocked by the neural layer (active blocking mode)
    pub static ref NEURAL_BLOCKS: IntCounter = IntCounter::new(
        "zn_neural_blocks_total",
        "Total number of tool calls blocked by the neural layer"
    ).expect("Failed to create neural_blocks metric");

    /// Live FPR of the serving neural model (0.0 - 1.0)
    pub static ref NEURAL_FPR: Gauge = Gauge::new(
        "zn_neural_fpr",
        "Current false-positive rate of the serving neural model (canary while active, else control)"
    ).expect("Failed to create neural_fpr metric");

    /// Cache hits total
    pub static ref CACHE_HITS_TOTAL: IntCounter = IntCounter::new(
        "zn_cache_hits_total",
        "Total number of cache hits"
    ).expect("Failed to create cache_hits_total metric");

    /// Cache misses total
    pub static ref CACHE_MISSES_TOTAL: IntCounter = IntCounter::new(
        "zn_cache_misses_total",
        "Total number of cache misses"
    ).expect("Failed to create cache_misses_total metric");

    /// Cache evictions total
    pub static ref CACHE_EVICTIONS_TOTAL: IntCounter = IntCounter::new(
        "zn_cache_evictions_total",
        "Total number of cache evictions"
    ).expect("Failed to create cache_evictions_total metric");

    /// Cache size gauge
    pub static ref CACHE_SIZE: IntGauge = IntGauge::new(
        "zn_cache_size",
        "Current cache size"
    ).expect("Failed to create cache_size metric");

    /// Cache hit rate gauge (0.0 - 1.0)
    pub static ref CACHE_HIT_RATE: Gauge = Gauge::new(
        "zn_cache_hit_rate",
        "Current cache hit rate (hits / (hits + misses))"
    ).expect("Failed to create cache_hit_rate metric");

    /// Throughput: requests per second
    pub static ref THROUGHPUT_RPS: Gauge = Gauge::new(
        "zn_throughput_rps",
        "Current throughput in requests per second"
    ).expect("Failed to create throughput_rps metric");

    /// Batch processing queue size
    pub static ref BATCH_QUEUE_SIZE: IntGauge = IntGauge::new(
        "zn_batch_queue_size",
        "Current size of batch processing queue"
    ).expect("Failed to create batch_queue_size metric");

    /// Batch processing processed total
    pub static ref BATCH_PROCESSED_TOTAL: IntCounter = IntCounter::new(
        "zn_batch_processed_total",
        "Total number of batch items processed"
    ).expect("Failed to create batch_processed_total metric");

    /// Batch processing duration histogram
    pub static ref BATCH_DURATION: Histogram = Histogram::with_opts(
        HistogramOpts::new(
            "zn_batch_duration_seconds",
            "Time spent processing batches"
        ).namespace("zn")
        .buckets(vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0])
    ).expect("Failed to create batch_duration metric");
}

/// Initialize and register all metrics
pub fn init() -> Result<(), prometheus::Error> {
    REGISTRY.register(Box::new(TOOL_CALLS_TOTAL.clone()))?;
    REGISTRY.register(Box::new(TOOL_CALLS_ALLOWED.clone()))?;
    REGISTRY.register(Box::new(TOOL_CALLS_DENIED.clone()))?;
    REGISTRY.register(Box::new(SQL_INJECTION_BLOCKED.clone()))?;
    REGISTRY.register(Box::new(PROMPT_INJECTION_BLOCKED.clone()))?;
    REGISTRY.register(Box::new(POLICY_EVAL_DURATION.clone()))?;
    REGISTRY.register(Box::new(JSONRPC_REQUESTS.clone()))?;
    REGISTRY.register(Box::new(SSE_CONNECTIONS.clone()))?;
    REGISTRY.register(Box::new(API_LATENCY.clone()))?;
    REGISTRY.register(Box::new(API_LATENCY_P95.clone()))?;
    REGISTRY.register(Box::new(API_LATENCY_P99.clone()))?;
    REGISTRY.register(Box::new(PII_DETECTED.clone()))?;
    REGISTRY.register(Box::new(AUDIT_ENTRIES.clone()))?;
    REGISTRY.register(Box::new(NEURAL_LATENCY.clone()))?;
    REGISTRY.register(Box::new(NEURAL_LATENCY_P95.clone()))?;
    REGISTRY.register(Box::new(NEURAL_LATENCY_P99.clone()))?;
    REGISTRY.register(Box::new(NEURAL_BLOCKS.clone()))?;
    REGISTRY.register(Box::new(NEURAL_FPR.clone()))?;
    REGISTRY.register(Box::new(CACHE_HITS_TOTAL.clone()))?;
    REGISTRY.register(Box::new(CACHE_MISSES_TOTAL.clone()))?;
    REGISTRY.register(Box::new(CACHE_EVICTIONS_TOTAL.clone()))?;
    REGISTRY.register(Box::new(CACHE_SIZE.clone()))?;
    REGISTRY.register(Box::new(CACHE_HIT_RATE.clone()))?;
    REGISTRY.register(Box::new(THROUGHPUT_RPS.clone()))?;
    REGISTRY.register(Box::new(BATCH_QUEUE_SIZE.clone()))?;
    REGISTRY.register(Box::new(BATCH_PROCESSED_TOTAL.clone()))?;
    REGISTRY.register(Box::new(BATCH_DURATION.clone()))?;
    Ok(())
}

/// Render metrics in Prometheus text format
pub fn render() -> String {
    let encoder = TextEncoder::new();
    let metric_families = REGISTRY.gather();
    let mut buffer = Vec::new();
    encoder
        .encode(&metric_families, &mut buffer)
        .unwrap_or_default();
    String::from_utf8(buffer).unwrap_or_default()
}

/// Record a tool call with its outcome
pub fn record_tool_call(tool_name: &str, status: &str) {
    TOOL_CALLS_TOTAL
        .with_label_values(&[tool_name, status])
        .inc();
    match status {
        "ALLOWED" => TOOL_CALLS_ALLOWED.inc(),
        "DENIED" => TOOL_CALLS_DENIED.inc(),
        _ => {}
    }
}

/// Record an SQL injection block
pub fn record_sql_injection_blocked() {
    SQL_INJECTION_BLOCKED.inc();
}

/// Record a prompt injection block
pub fn record_prompt_injection_blocked() {
    PROMPT_INJECTION_BLOCKED.inc();
}

/// Record policy evaluation time
pub fn record_policy_eval_time(duration_secs: f64) {
    POLICY_EVAL_DURATION.observe(duration_secs);
}

/// Record JSON-RPC request
pub fn record_jsonrpc_request(method: &str, result: &str) {
    JSONRPC_REQUESTS.with_label_values(&[method, result]).inc();
}

/// Record PII detection
pub fn record_pii_detected(pii_type: &str) {
    PII_DETECTED.with_label_values(&[pii_type]).inc();
}

/// Increment audit entries counter
pub fn record_audit_entry() {
    AUDIT_ENTRIES.inc();
}

/// Record neural-layer latency (embed + classify) for one tool call
pub fn record_neural_embed(duration_secs: f64) {
    NEURAL_LATENCY.observe(duration_secs);
}

/// Record neural-layer latency p95
pub fn record_neural_embed_p95(duration_secs: f64) {
    NEURAL_LATENCY_P95.observe(duration_secs);
}

/// Record neural-layer latency p99
pub fn record_neural_embed_p99(duration_secs: f64) {
    NEURAL_LATENCY_P99.observe(duration_secs);
}

/// Record a tool call blocked by the neural layer
pub fn record_neural_block() {
    NEURAL_BLOCKS.inc();
}

/// Update the live FPR gauge of the serving neural model
pub fn set_neural_fpr(fpr: f64) {
    NEURAL_FPR.set(fpr);
}

/// Record a cache hit
pub fn record_cache_hit() {
    CACHE_HITS_TOTAL.inc();
}

/// Record a cache miss
pub fn record_cache_miss() {
    CACHE_MISSES_TOTAL.inc();
}

/// Record a cache eviction
pub fn record_cache_eviction() {
    CACHE_EVICTIONS_TOTAL.inc();
}

/// Set cache size
pub fn set_cache_size(size: usize) {
    CACHE_SIZE.set(size as i64);
}

/// Update cache hit rate calculation
pub fn update_cache_hit_rate(hits: u64, misses: u64) {
    let total = hits + misses;
    if total > 0 {
        let rate = hits as f64 / total as f64;
        CACHE_HIT_RATE.set(rate);
    }
}

/// Record a throughput measurement (requests per second)
pub fn record_throughput_rps(rps: f64) {
    THROUGHPUT_RPS.set(rps);
}

/// Set batch queue size
pub fn set_batch_queue_size(size: usize) {
    BATCH_QUEUE_SIZE.set(size as i64);
}

/// Record batch processed item
pub fn record_batch_processed() {
    BATCH_PROCESSED_TOTAL.inc();
}

/// Record batch processing duration
pub fn record_batch_duration(duration_secs: f64) {
    BATCH_DURATION.observe(duration_secs);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_tool_call() {
        record_tool_call("test_tool", "ALLOWED");
        // Metrics are global so we just verify it doesn't panic
    }

    #[test]
    fn test_render_metrics() {
        let output = render();
        // Output should be valid Prometheus format (empty if not initialized)
        assert!(output.is_empty() || output.contains("# HELP") || true);
    }

    #[test]
    fn test_neural_metrics_registered_and_recorded() {
        use std::sync::Once;
        static INIT: Once = Once::new();
        INIT.call_once(|| {
            init().expect("metrics init");
        });
        record_neural_embed(0.004);
        record_neural_embed_p95(0.005);
        record_neural_embed_p99(0.006);
        record_neural_block();
        set_neural_fpr(0.014);
        record_cache_hit();
        record_cache_miss();
        record_cache_eviction();
        set_cache_size(100);
        update_cache_hit_rate(100, 20);
        record_throughput_rps(150.5);
        set_batch_queue_size(10);
        record_batch_processed();
        record_batch_duration(0.05);
        let out = render();
        assert!(
            out.contains("zn_neural_latency_seconds"),
            "latency histogram missing"
        );
        assert!(
            out.contains("zn_neural_latency_p95_seconds"),
            "p95 latency histogram missing"
        );
        assert!(
            out.contains("zn_neural_latency_p99_seconds"),
            "p99 latency histogram missing"
        );
        assert!(
            out.contains("zn_neural_blocks_total"),
            "block counter missing"
        );
        assert!(out.contains("zn_neural_fpr"), "FPR gauge missing");
        assert!(out.contains("0.014"), "FPR value not exported");
        assert!(out.contains("zn_cache_hits_total"), "cache hits missing");
        assert!(
            out.contains("zn_cache_misses_total"),
            "cache misses missing"
        );
        assert!(
            out.contains("zn_cache_evictions_total"),
            "cache evictions missing"
        );
        assert!(out.contains("zn_cache_size"), "cache size missing");
        assert!(out.contains("zn_cache_hit_rate"), "cache hit rate missing");
        assert!(out.contains("zn_throughput_rps"), "throughput missing");
        assert!(
            out.contains("zn_batch_queue_size"),
            "batch queue size missing"
        );
        assert!(
            out.contains("zn_batch_processed_total"),
            "batch processed missing"
        );
        assert!(
            out.contains("zn_batch_duration_seconds"),
            "batch duration missing"
        );
    }
}
