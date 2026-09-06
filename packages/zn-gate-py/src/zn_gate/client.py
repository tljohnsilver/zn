"""
zn-gate client module: Hybrid inspection engine combining local deterministic rules (<10µs)
with optional deep neural cloud inspection. Pure Python stdlib. Zero external dependencies.
"""

from __future__ import annotations

import json
import os
import urllib.request
import urllib.error
from typing import Any, Dict, Optional

from .rules import evaluate, Assessment, RULES_VERSION

DEFAULT_ENDPOINT = "https://api.usezn.com/v30/analyze"


def resolve_endpoint(options: Optional[Dict[str, Any]] = None) -> str:
    options = options or {}
    if "api_url" in options and options["api_url"]:
        return options["api_url"]
    if os.environ.get("ZN_API_URL"):
        return os.environ["ZN_API_URL"]
    stage = options.get("stage") or os.environ.get("ZN_STAGE") or "v30"
    if stage == "prod":
        return "https://api.usezn.com/prod/analyze"
    return DEFAULT_ENDPOINT


def analyze_cloud(
    input_text: str,
    api_key: str,
    endpoint_url: Optional[str] = None,
    timeout: float = 4.0,
) -> Dict[str, Any]:
    """Sends payload to zn Cloud Gate using pure stdlib urllib."""
    endpoint = endpoint_url or DEFAULT_ENDPOINT
    payload = json.dumps({"input": input_text}).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key.strip()}",
        "User-Agent": "zn-gate/1.2.4 (python-stdlib-client)",
    }
    req = urllib.request.Request(endpoint, data=payload, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read().decode("utf-8")
        parsed = json.loads(body)
        parsed["engine"] = "cloud-v30" if "/v30" in endpoint else "cloud-prod"
        return parsed


def analyze(
    input_text: str,
    api_key: Optional[str] = None,
    endpoint: Optional[str] = None,
    timeout: float = 4.0,
    local_only: bool = False,
    **kwargs: Any,
) -> Dict[str, Any]:
    """
    Hybrid analysis: evaluates in-process local deterministic rules in <10µs.
    If local rules block -> immediately short-circuits with 0 network latency.
    If local rules allow & api_key is present -> queries Cloud Gate for neural multilingual scan.
    """
    key = api_key or os.environ.get("ZN_API_KEY")
    force_local = local_only or os.environ.get("ZN_LOCAL_ONLY") == "true"

    # 1. Local fast-path (<10µs, $0 cost)
    local_eval = evaluate(input_text)
    if not local_eval.allowed:
        return {
            "verdict": "block",
            "confidence": local_eval.confidence,
            "rule": local_eval.rule,
            "reason": local_eval.reason,
            "mode": "hybrid-local-fastpath",
            "engine": "oss-local",
            "rules_version": local_eval.rules_version,
            "latency_us": 5,
        }

    # If no API key or local only, return local allow
    if not key or force_local:
        return {
            "verdict": "allow",
            "confidence": local_eval.confidence,
            "rule": "none",
            "reason": None,
            "mode": "oss-local",
            "engine": "oss-local",
            "rules_version": local_eval.rules_version,
            "tip": "Set ZN_API_KEY to enable neural multilingual protection via usezn cloud gate",
        }

    # 2. Cloud Gate deep neural analysis
    target_url = endpoint or resolve_endpoint(kwargs)
    try:
        cloud_res = analyze_cloud(input_text, key, target_url, timeout=timeout)
        cloud_res["mode"] = "hybrid-cloud"
        return cloud_res
    except Exception as exc:
        if os.environ.get("DEBUG") or os.environ.get("ZN_VERBOSE"):
            import sys
            sys.stderr.write(f"[zn-gate] Warning: Cloud gate error ({exc}). Using local OSS rules fallback.\n")
        return {
            "verdict": "allow",
            "confidence": local_eval.confidence,
            "rule": "none",
            "reason": None,
            "mode": "oss-local-fallback",
            "engine": "oss-local",
            "fallback": True,
            "cloud_error": str(exc),
        }
