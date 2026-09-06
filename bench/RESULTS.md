# zn-gate Benchmark Results

Date: 2026-09-06 · Engine: zn-gate v1.2.3 (rules-only, no network) · Host: EC2
Method: 20,000 UNIQUE mixed samples (EN/ES/FR/ZH attacks + benign code/SQL/PII)
— every call is a cache miss + insert (includes LRU eviction churn past 2048 entries).

| Engine | Throughput (miss) | Cache hit p50 | Cache hit p99 | Targets | Verdict |
|---|---|---|---|---|---|
| Node.js `evaluate()` | 73,572 prompts/s | 4.89 µs | 17.55 µs | >50k/s, hit <40µs | PASS |
| Python `evaluate()` | 15,185 prompts/s | 0.91 µs | 2.17 µs | >10k/s, hit <40µs | PASS |

Cache: LRU-2048 keyed on raw input, version-guarded (RULES_VERSION) + config-guarded
(Node: custom-config object identity). Hit returns a copy — caller mutation is safe.
Reproduce: `node bench/bench_node.js [iters]` · `python3 bench/bench_python.py [iters]`
