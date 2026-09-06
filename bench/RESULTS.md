# zn-gate Benchmark Results

Date: 2026-09-06 · Engine: zn-gate v1.2.3 (rules-only, no network) · Host: EC2
Method: 20,000 mixed samples (EN/ES/FR/ZH attacks + benign code/SQL/PII), 1k warmup.

| Engine | Throughput | p50 | p95 | p99 | Target | Verdict |
|---|---|---|---|---|---|---|
| Node.js `evaluate()` | 114,601 prompts/s | 5.95 µs | 9.85 µs | 32.58 µs | > 50,000/s | PASS |
| Python `evaluate()` | 17,783 prompts/s | 45.28 µs | 89.91 µs | 271.22 µs | > 10,000/s | PASS |

Reproduce: `node bench/bench_node.js [iters]` · `python3 bench/bench_python.py [iters]`
