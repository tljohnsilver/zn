"""
Cryptographic Evidence Engine for zn-gate-py.
Maintains a tamper-evident SHA-256 hash-chained audit ledger at ~/.zn/evidence.jsonl.
Pure Python stdlib. Zero external dependencies.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

ZN_DIR = os.path.expanduser("~/.zn")
EVIDENCE_FILE = os.path.join(ZN_DIR, "evidence.jsonl")
GENESIS_HASH = "0" * 64


def _ensure_dir(file_path: str) -> None:
    dirname = os.path.dirname(file_path)
    if dirname and not os.path.exists(dirname):
        os.makedirs(dirname, exist_ok=True)


def get_last_hash(file_path: str = EVIDENCE_FILE) -> str:
    """Reads the record_hash of the last line in the ledger."""
    if not os.path.exists(file_path):
        return GENESIS_HASH
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]
        if not lines:
            return GENESIS_HASH
        last_rec = json.loads(lines[-1])
        return last_rec.get("record_hash", GENESIS_HASH)
    except Exception:
        return GENESIS_HASH


def log_evidence(event: Dict[str, Any], file_path: str = EVIDENCE_FILE) -> Dict[str, Any]:
    """
    Appends a cryptographically hash-chained evidence record to the ledger.
    Formula: record_hash = sha256(prev_hash + ":" + json(base_record))
    """
    _ensure_dir(file_path)
    prev_hash = get_last_hash(file_path)
    timestamp = datetime.now(timezone.utc).isoformat()
    record_id = f"ev_{int(time.time() * 1000):x}_{secrets.token_hex(4)}"

    payload_raw = event.get("payload", "")
    payload_str = payload_raw if isinstance(payload_raw, str) else json.dumps(payload_raw, separators=(",", ":"))
    payload_sha256 = hashlib.sha256(payload_str.encode("utf-8")).hexdigest()

    raw_conf = event.get("confidence", 1.0)
    conf_val = int(raw_conf) if isinstance(raw_conf, (int, float)) and float(raw_conf).is_integer() else float(raw_conf)

    base_record = {
        "id": record_id,
        "timestamp": timestamp,
        "agent_environment": event.get("agent") or event.get("agent_environment") or "python-agent",
        "phase": event.get("phase", "tool-call"),
        "tool_name": event.get("tool_name") or event.get("tool") or "unknown",
        "payload_sha256": payload_sha256,
        "payload_preview": payload_str[:120],
        "verdict": event.get("verdict", "allow"),
        "rule": event.get("rule", None),
        "reason": event.get("reason", None),
        "confidence": conf_val,
        "latency_us": int(event.get("latency_us", 0)),
        "engine": event.get("engine", "python-deterministic"),
        "prev_hash": prev_hash,
    }

    serialized_base = json.dumps(base_record, separators=(",", ":"))
    hash_input = f"{prev_hash}:{serialized_base}".encode("utf-8")
    record_hash = hashlib.sha256(hash_input).hexdigest()

    final_record = dict(base_record)
    final_record["record_hash"] = record_hash

    with open(file_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(final_record, separators=(",", ":")) + "\n")

    return final_record


def verify_evidence_ledger(file_path: str = EVIDENCE_FILE) -> Dict[str, Any]:
    """
    Verifies the cryptographic integrity of the entire ledger chain from genesis.
    Returns { "valid": bool, "total": int, "verified": int, "broken_index": Optional[int], "error": Optional[str] }
    """
    if not os.path.exists(file_path):
        return {"valid": True, "total": 0, "verified": 0, "broken_index": None, "error": None}

    with open(file_path, "r", encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip()]

    expected_prev = GENESIS_HASH

    for i, line in enumerate(lines):
        try:
            rec = json.loads(line)
        except Exception as e:
            return {
                "valid": False,
                "total": len(lines),
                "verified": i,
                "broken_index": i,
                "error": f"Malformed JSON at line {i+1}: {e}",
            }

        rec_prev = rec.get("prev_hash")
        if rec_prev != expected_prev:
            return {
                "valid": False,
                "total": len(lines),
                "verified": i,
                "broken_index": i,
                "error": f"Broken chain link at line {i+1} (record {rec.get('id')}): expected {expected_prev[:8]}... found {str(rec_prev)[:8]}...",
            }

        recorded_hash = rec.get("record_hash")
        base_record = {k: v for k, v in rec.items() if k != "record_hash"}
        # Ensure confidence preserves whole number integer representation if whole
        if "confidence" in base_record and isinstance(base_record["confidence"], (int, float)) and float(base_record["confidence"]).is_integer():
            base_record["confidence"] = int(base_record["confidence"])
            
        serialized_base = json.dumps(base_record, separators=(",", ":"))
        computed_hash = hashlib.sha256(f"{expected_prev}:{serialized_base}".encode("utf-8")).hexdigest()

        if computed_hash != recorded_hash:
            return {
                "valid": False,
                "total": len(lines),
                "verified": i,
                "broken_index": i,
                "error": f"Tamper detected at line {i+1} (record {rec.get('id')}): hash mismatch! Log contents were modified.",
            }

        expected_prev = recorded_hash

    return {"valid": True, "total": len(lines), "verified": len(lines), "broken_index": None, "error": None}


def get_evidence_stats(file_path: str = EVIDENCE_FILE, limit: int = 50) -> Dict[str, Any]:
    """Generates aggregated stats from the evidence ledger."""
    if not os.path.exists(file_path):
        return {
            "total": 0,
            "blocks": 0,
            "allows": 0,
            "shadows": 0,
            "valid": True,
            "top_rules": {},
            "top_tools": {},
            "recent": [],
        }

    with open(file_path, "r", encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip()]

    blocks = 0
    allows = 0
    shadows = 0
    top_rules: Dict[str, int] = {}
    top_tools: Dict[str, int] = {}
    recent: List[Dict[str, Any]] = []

    for line in reversed(lines):
        try:
            rec = json.loads(line)
            v = rec.get("verdict")
            if v == "block":
                blocks += 1
                r = rec.get("rule")
                if r:
                    top_rules[r] = top_rules.get(r, 0) + 1
            elif v == "shadow":
                shadows += 1
            else:
                allows += 1

            t = rec.get("tool_name")
            if t:
                top_tools[t] = top_tools.get(t, 0) + 1

            if len(recent) < limit:
                recent.append(rec)
        except Exception:
            continue

    check = verify_evidence_ledger(file_path)

    return {
        "total": len(lines),
        "blocks": blocks,
        "allows": allows,
        "shadows": shadows,
        "valid": check["valid"],
        "top_rules": top_rules,
        "top_tools": top_tools,
        "recent": recent,
    }
