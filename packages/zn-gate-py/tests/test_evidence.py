import json
import os
import shutil
import tempfile
import pytest

from zn_gate.evidence import log_evidence, verify_evidence_ledger, get_evidence_stats, export_evidence_ledger, GENESIS_HASH


def test_evidence_engine_append_and_verify():
    tmp_dir = tempfile.mkdtemp(prefix="zn_ev_py_test_")
    test_ledger = os.path.join(tmp_dir, "evidence.jsonl")

    try:
        rec1 = log_evidence(
            {
                "agent": "langchain-agent",
                "phase": "tool-call",
                "tool_name": "bash",
                "payload": "cat ~/.ssh/id_rsa",
                "verdict": "block",
                "rule": "LFI_SSH_PATTERN",
                "confidence": 1.0,
                "latency_us": 25,
                "engine": "python-deterministic",
            },
            file_path=test_ledger,
        )

        assert rec1["prev_hash"] == GENESIS_HASH
        assert len(rec1["record_hash"]) == 64
        assert rec1["verdict"] == "block"

        rec2 = log_evidence(
            {
                "agent": "crewai",
                "phase": "tool-result",
                "tool_name": "postgres",
                "payload": "SELECT 1",
                "verdict": "allow",
                "confidence": 1.0,
                "latency_us": 10,
                "engine": "python-deterministic",
            },
            file_path=test_ledger,
        )

        assert rec2["prev_hash"] == rec1["record_hash"]
        assert len(rec2["record_hash"]) == 64

        stats = get_evidence_stats(test_ledger)
        assert stats["total"] == 2
        assert stats["blocks"] == 1
        assert stats["allows"] == 1

        check = verify_evidence_ledger(test_ledger)
        assert check["valid"] is True
        assert check["total"] == 2
        assert check["verified"] == 2

    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def test_evidence_engine_tamper_detection():
    tmp_dir = tempfile.mkdtemp(prefix="zn_ev_py_tamper_")
    test_ledger = os.path.join(tmp_dir, "evidence.jsonl")

    try:
        log_evidence({"agent": "a", "tool_name": "t1", "verdict": "block", "rule": "R1"}, file_path=test_ledger)
        log_evidence({"agent": "b", "tool_name": "t2", "verdict": "allow"}, file_path=test_ledger)
        log_evidence({"agent": "c", "tool_name": "t3", "verdict": "block", "rule": "R2"}, file_path=test_ledger)

        initial_check = verify_evidence_ledger(test_ledger)
        assert initial_check["valid"] is True
        assert initial_check["total"] == 3

        # Tamper record 0 (change block to allow)
        with open(test_ledger, "r", encoding="utf-8") as f:
            lines = [l.strip() for l in f if l.strip()]

        rec0 = json.loads(lines[0])
        rec0["verdict"] = "allow"
        lines[0] = json.dumps(rec0, separators=(",", ":"))

        with open(test_ledger, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")

        tampered_check = verify_evidence_ledger(test_ledger)
        assert tampered_check["valid"] is False
        assert tampered_check["broken_index"] == 0

    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def test_evidence_engine_export():
    tmp_dir = tempfile.mkdtemp(prefix="zn_ev_py_export_")
    test_ledger = os.path.join(tmp_dir, "evidence.jsonl")

    try:
        log_evidence({"agent": "agent-a", "phase": "tool-call", "tool_name": "bash", "payload": "whoami", "verdict": "allow", "latency_us": 15}, file_path=test_ledger)
        log_evidence({"agent": "agent-b", "phase": "tool-call", "tool_name": "bash", "payload": "cat /etc/passwd", "verdict": "block", "rule": "path:sensitive_file", "latency_us": 20}, file_path=test_ledger)

        jsonl_exp = export_evidence_ledger(test_ledger, format="jsonl")
        assert jsonl_exp["format"] == "jsonl"
        assert jsonl_exp["valid"] is True
        assert jsonl_exp["total"] == 2
        assert "whoami" in jsonl_exp["content"]
        assert "path:sensitive_file" in jsonl_exp["content"]

        csv_exp = export_evidence_ledger(test_ledger, format="csv")
        assert csv_exp["format"] == "csv"
        assert csv_exp["valid"] is True
        assert csv_exp["total"] == 2
        assert csv_exp["content"].startswith("timestamp,verdict,phase,tool_name")
        assert '"allow"' in csv_exp["content"]
        assert '"block"' in csv_exp["content"]
        assert '"path:sensitive_file"' in csv_exp["content"]

    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
