# zn Industry Benchmark Evaluation & Cryptographic Hashes
> **Date**: 2026-09-06 16:25:56 UTC
> **Release Target**: zn-gate v1.2.3 (npm / PyPI)
> **Evaluator**: Standardized test harness (`bench_industry.py`)

---

## 1. Unified Industry Benchmark Matrix

Comparison across identical datasets between **zn Core 1.2.3** (local zero-dependency rules), **Meta Prompt Guard 2 (22M)**, and **zn Cloud Gate (v30 Neural)**:

| Benchmark Dataset | Threat / Scope | $N$ | **zn Core 1.2.3** *(Local OSS)* | **Meta Prompt Guard 2** *(22M)* | **zn Cloud Gate** *(v30 Neural)* |
|---|---|---|---|---|---|
| **`deepset/prompt-injections`** | Direct injection & benign | 116 | **TPR: 23.3% · FPR: 0.00%** | TPR: 89.2% · FPR: 4.10% | **TPR: 96.5% · FPR: 0.80%** |
| **`InjecAgent`** (UIUC Kang Lab) | Indirect prompt injection in tools | 1,054 | **Recall: 1.61%** *(Regex baseline)* | Recall: 58.7% · FPR: 6.40% | **Recall: 92.4% · FPR: 1.10%** |
| **Benign Tool Results Suite** | Real tool returns (Calendar, SQL, Slack) | 400 | **FPR: 0.00%** *(0 / 400 alerts)* | FPR: 4.25% *(17 / 400)* | **FPR: 0.25%** *(1 / 400)* |
| **Developer Controls (`regress`)** | Engineering code with trigger words | 623 | **FPR: 0.00%** *(0 / 623 alerts)* | FPR: 5.14% *(32 / 623)* | **FPR: 0.64%** *(4 / 623)* |
| **`znRed v2 Fuzzer`** | Obfuscation (homoglyphs, ZWSP, HTML) | 1,500 | **Block: 97.93%** *(1,469 / 1,500)* | Block: 71.40% | **Block: 99.10%** |
| **Latency (p50 in-process)** | Execution overhead | — | **< 0.05 ms** *(4.9 µs hit)* | ~18.5 ms (CPU) | **~18 ms** (Lambda INT8) |
| **Dependencies & Footprint** | System footprint | — | **0 external dependencies** (15 kB) | PyTorch + Transformers (~1.8 GB) | Managed HTTPS endpoint |

---

## 2. Dataset Cryptographic Hashes (SHA-256)

For verifiable third-party reproducibility, the evaluated datasets have the following exact SHA-256 checksums:

```
394286c5bd2e0b21eb1719d7ec25e3d5a14290c6c2ace52c7f23d74337851823  deepset_test.json (116 rows)
0a8186468d21389af432e8c7b399ae42264d1b93a07b65c7a489468508604305  InjecAgent/test_cases_dh_base.json (510 Direct Harm cases)
4daab35c62a3845e8b9400f4dca58b9c9f37e57cd33b2337552557fbb26282e9  InjecAgent/test_cases_ds_base.json (544 Data Stealing cases)
b1da2e1fb75f266c069b832fef6738c295f01d8962fae15bdac9ff6625e5594e  InjecAgent/attacker_simulated_responses.json (2,347 simulated tool returns)
5e61894fe68c526e1540397ec567a4b50305f73930f5a19a5d6c395a17f90db2  benign_tool_results_400.json (400 clean tool outputs)
```

---

## 3. Key Findings

1. **Zero False Positives on Benign Tool Execution**:
   Testing 400 diverse JSON tool outputs (Google Calendar, Weather, PostgreSQL orders, Slack messages, GitHub commits) yielded **0 false positive blocks** in zn Core (`FPR: 0.00%`).
2. **Complementary Layer Architecture**:
   zn Core 1.2.3 provides sub-millisecond, zero-dependency, zero-FP protection against explicit jailbreaks, exfiltration commands, and obfuscated evasions (`97.93%` on znRed v2). The Neural Cloud Gate provides deep semantic defense on natural-language indirect tool injections (`92.4%` on InjecAgent).
