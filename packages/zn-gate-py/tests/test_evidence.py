import json
import os
import tempfile
import pytest

from zn_gate.evidence import (
    log_evidence,
    verify_evidence_ledger,
    get_evidence_stats,
    GENESIS_HASH,
)


def test_log_evidence_creates_sha256_chain():
    with tempfile.TemporaryDirectory() as tmp_dir:
        ledger_file = os.path.join(tmp_dir, "evidence.jsonl")

        rec1 = log_evidence(
            {
                "agent": "crewai-agent",
                "phase": "tool-call",
                "tool_name": "bash",
                "payload": "cat ~/.ssh/id_rsa",
                "verdict": "block",
                "rule": "LFI_SSH_PATTERN",
                "latency_us": 18,
            },
            file_path=ledger_file,
        )

        assert rec1["prev_hash"] == GENESIS_HASH
        assert len(rec1["record_hash"]) == 64
        assert rec1["verdict"] == "block"

        rec2 = log_evidence(
            {
                "agent": "langchain-agent",
                "phase": "tool-result",
                "tool_name": "sql_query",
                "payload": "SELECT 1;",
                "verdict": "allow",
                "latency_us": 9,
            },
            file_path=ledger_file,
        )

        assert rec2["prev_hash"] == rec1["record_hash"]
        assert len(rec2["record_hash"]) == 64
        assert rec2["verdict"] == "allow"

        # Verify ledger integrity
        check = verify_evidence_ledger(ledger_file)
        assert check["valid"] is True
        assert check["total"] == 2
        assert check["broken_index"] is None

        # Verify stats
        stats = get_evidence_stats(ledger_file)
        assert stats["total"] == 2
        assert stats["blocks"] == 1
        assert stats["allows"] == 1


def test_tamper_detection_in_evidence_ledger():
    with tempfile.TemporaryDirectory() as tmp_dir:
        ledger_file = os.path.join(tmp_dir, "evidence.jsonl")

        log_evidence({"agent": "a1", "verdict": "block", "rule": "R1"}, file_path=ledger_file)
        log_evidence({"agent": "a2", "verdict": "allow"}, file_path=ledger_file)
        log_evidence({"agent": "a3", "verdict": "block", "rule": "R2"}, file_path=ledger_file)

        # Baseline check is valid
        assert verify_evidence_ledger(ledger_file)["valid"] is True

        # Malicious modification: change record 0 verdict from 'block' to 'allow'
        with open(ledger_file, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]

        rec0 = json.loads(lines[0])
        rec0["verdict"] = "allow"
        lines[0] = json.dumps(rec0, separators=(",", ":"))

        with open(ledger_file, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")

        # Must detect tamper!
        tampered_check = verify_evidence_ledger(ledger_file)
        assert tampered_check["valid"] is False
        assert tampered_check["broken_index"] == 0
        assert "Tamper detected" in tampered_check["error"]
