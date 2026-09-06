"""
zn deterministic rules engine - Python stdlib implementation.
RULES_VERSION: 2026-09-06.3
Zero external dependencies. Pure Python stdlib.
"""

from __future__ import annotations

import base64
import json
import os
import re
import sys
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Tuple

RULES_VERSION = "2026-09-06.3"

# Cyrillic homoglyphs mapping to Latin
HOMOGLYPH_MAP = {
    '\u0430': 'a', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p', '\u0441': 'c',
    '\u0456': 'i', '\u0455': 's', '\u0443': 'y', '\u0445': 'x',
    '\u0410': 'A', '\u0415': 'E', '\u041e': 'O', '\u0420': 'P', '\u0421': 'C',
}

ZERO_WIDTH_RE = re.compile(r'[\u200B-\u200D\uFEFF\u00AD]')
C_COMMENT_RE = re.compile(r'/\*[\s\S]*?\*/')
DELIMITER_SPLIT_RE = re.compile(r'([\w<|/.-]{1,})\s*[\r\n]+\s*([\w>|/.-]{1,})', re.UNICODE)
B64_EXEC_RE = re.compile(r'(?:echo|printf)\s+([A-Za-z0-9+/=]{16,})\s*\|\s*(?:base64\s+-(?:d|-decode)|openssl)', re.IGNORECASE)

INJECTION_RULES: List[Tuple[str, re.Pattern, str]] = [
    ('pi:ignore_previous', re.compile(r'ignore\s+(all\s+)?(the\s+)?(previous|prior|above|existing|system)?\s*(instructions|prompts|rules|guidelines|context)?', re.IGNORECASE), 'Override prior instructions'),
    ('pi:disregard', re.compile(r'disregard\s+(all\s+)?(the\s+)?(previous|prior|above)?\s*(guidelines|instructions|rules|prompts)?', re.IGNORECASE), 'Disregard instructions'),
    ('pi:forget', re.compile(r'forget\s+(about\s+)?(everything|all|your)', re.IGNORECASE), 'Forget-context attack'),
    ('pi:identity_override', re.compile(r'you\s+are\s+now', re.IGNORECASE), 'Identity override'),
    ('pi:new_instructions', re.compile(r'new\s+instructions?:', re.IGNORECASE), 'Instruction replacement'),
    ('pi:system_tag', re.compile(r'(?:^|[\r\n"\'`\[<])\s*system\s*:|<[\s/]*system\b[^>]*>', re.IGNORECASE), 'Fake system tag'),
    ('pi:system_bracket', re.compile(r'\[system\]', re.IGNORECASE), 'Bracketed system tag'),
    ('pi:act_as', re.compile(r'act\s+as\s+(if|a)', re.IGNORECASE), 'Role hijack (act as)'),
    ('pi:pretend', re.compile(r'pretend\s+(you|to\s+be)', re.IGNORECASE), 'Role hijack (pretend)'),
    ('pi:roleplay', re.compile(r'roleplay\s+as', re.IGNORECASE), 'Role hijack (roleplay)'),
    ('pi:jailbreak', re.compile(r'\bjailbreak\b', re.IGNORECASE), 'Explicit jailbreak term'),
    ('pi:bypass', re.compile(r'bypass\s+(your|the|all)', re.IGNORECASE), 'Guardrail bypass attempt'),
    ('pi:override', re.compile(r'\b(?:system\s+)?override\s+(?:your|the|all|system|policy|rules|instructions|safety|guidelines)\b|\bsystem\s+override\s*:', re.IGNORECASE), 'Policy override attempt'),
    ('pi:template_boundary', re.compile(r'\[INST\]|\[/INST\]|<<<SYS>>>|</<<SYS>>>|<\|im_start\|>|<\|im_end\|>', re.IGNORECASE), 'Chat template boundary injection'),
    ('pi:multi_es', re.compile(r'ignora\s+(todas\s+las\s+)?(instrucciones|anteriores|previas)|olvida\s+(todo|las\s+instrucciones)|act[uú]a\s+como|ahora\s+eres', re.IGNORECASE), 'Multilingual prompt injection (Spanish)'),
    ('pi:multi_fr', re.compile(r'ignore[rz]?\s+(toutes\s+les\s+)?instructions|oublie[rz]?\s+tout|agis\s+comme|tu\s+es\s+maintenant', re.IGNORECASE), 'Multilingual prompt injection (French)'),
    ('pi:multi_ru', re.compile(r'забудь\s+.*?(все|инструкции)|игнорируй\s+.*?(все|предыдущие)|действуй\s+как|ты\s+теперь|найди\s+пароли', re.IGNORECASE), 'Multilingual prompt injection (Russian)'),
    ('pi:multi_zh', re.compile(r'忽略.*?(指示|指令|提示)|忘记.*?(指示|指令|一切)|你现在是|初始提示词', re.IGNORECASE), 'Multilingual prompt injection (Chinese)'),
]

INDIRECT_INJECTION_RULES: List[Tuple[str, re.Pattern, str]] = [
    (
        'indirect:html_comment',
        re.compile(r'<!--\s*(?:system|instruction|prompt|override|command)\s*:', re.IGNORECASE),
        'Hidden instruction in HTML comment',
    ),
    (
        'indirect:hidden_tag',
        re.compile(r'<[a-z0-9]+\b[^>]*\b(?:display\s*:\s*none|visibility\s*:\s*hidden|hidden\b)[^>]*>[\s\S]*?(?:ignore|system|instruction|prompt|bypass|override)', re.IGNORECASE),
        'Hidden DOM element with injection payload',
    ),
]

EXFIL_VERBS = re.compile(r'\b(give|reveal|send|show|print|expose|leak|paste|dump|read|open|cat|fetch|extract|steal)\b', re.IGNORECASE)
CRED_OBJECTS = re.compile(r'\b(passwords?|api[_ -]?keys?|secrets?|credentials?|tokens?|ssh[ _-]?keys?|private[ _-]?keys?|aws_secret[a-z0-9_]*|aws_access[a-z0-9_]*)\b|(?:^|\s|[\'"`])\.env(?:\.[a-z0-9]+)?\b', re.IGNORECASE)

SENSITIVE_PATH_RULES: List[Tuple[str, re.Pattern, str]] = [
    (
        'path:sensitive_file',
        re.compile(r'(?:^|[\s"\'`(\[])(?:~|/home/[^\s/]+|/root)?/?\.(?:ssh/(?:id_rsa|id_ed25519|authorized_keys)|aws/credentials|env(?:\.[a-z0-9]+)?)\b|/etc/(?:shadow|passwd)\b', re.IGNORECASE),
        'Targeting sensitive system credentials or environment file',
    ),
]

MARKDOWN_EXFIL_RULES: List[Tuple[str, re.Pattern, str]] = [
    (
        'exfil:markdown_image',
        re.compile(r'!\[[^\]]*\]\(https?://[^\s)]+[\?&](?:key|token|pass|secret|cred|data|val|leak|exfil)=[^)]*\)', re.IGNORECASE),
        'Covert exfiltration via markdown image URL parameter',
    ),
]

@dataclass
class Assessment:
    verdict: str  # 'allow' | 'block'
    confidence: float
    rule: str
    reason: Optional[str]
    engine: str = 'oss-local'
    rules_version: str = RULES_VERSION

    @property
    def allowed(self) -> bool:
        return self.verdict == 'allow'

    def to_dict(self) -> Dict[str, Any]:
        return {
            'verdict': self.verdict,
            'confidence': self.confidence,
            'rule': self.rule,
            'reason': self.reason,
            'engine': self.engine,
            'rules_version': self.rules_version,
            'allowed': self.allowed,
        }

def normalize_input(text: str) -> Tuple[str, str]:
    if not isinstance(text, str):
        return '', ''
    # 1. Strip zero-width evasion characters
    stripped = ZERO_WIDTH_RE.sub('', text)
    # 2. Strip inline C-style comments (e.g. sys/*safe*/tem -> system)
    stripped = C_COMMENT_RE.sub('', stripped)
    # 3. Rejoin words and tokens split across newlines
    stripped = DELIMITER_SPLIT_RE.sub(r'\1\2', stripped)
    # 4. Normalize homoglyphs (Cyrillic to Latin for English hijack detection)
    normalized = "".join(HOMOGLYPH_MAP.get(c, c) for c in stripped)
    return normalized, stripped

def _evaluate_uncached(input_text: str) -> Assessment:
    if not isinstance(input_text, str) or not input_text.strip():
        return Assessment(verdict='allow', confidence=1.0, rule='none', reason=None)

    normalized, stripped = normalize_input(input_text)

    # Check Base64 payload smuggling
    for text_candidate in (normalized, stripped):
        b64_match = B64_EXEC_RE.search(text_candidate)
        if b64_match:
            try:
                decoded = base64.b64decode(b64_match.group(1)).decode('utf-8', errors='ignore')
                inner_res = evaluate(decoded)
                if not inner_res.allowed:
                    return Assessment(
                        verdict='block',
                        confidence=inner_res.confidence,
                        rule='evasion:base64_smuggling',
                        reason=f'Smuggled Base64 execution: {inner_res.reason or inner_res.rule}'
                    )
            except Exception:
                pass

    targets = list(dict.fromkeys([normalized, stripped, input_text]))

    for text in targets:
        # 1. Covert Markdown Image Exfiltration
        for rule_id, pat, desc in MARKDOWN_EXFIL_RULES:
            if pat.search(text):
                return Assessment(verdict='block', confidence=0.98, rule=rule_id, reason=desc)

        # 2. Sensitive Path Traversal
        for rule_id, pat, desc in SENSITIVE_PATH_RULES:
            if pat.search(text):
                return Assessment(verdict='block', confidence=0.92, rule=rule_id, reason=desc)

        # 3. Indirect Injections (HTML comments & hidden tags)
        for rule_id, pat, desc in INDIRECT_INJECTION_RULES:
            if pat.search(text):
                return Assessment(verdict='block', confidence=0.95, rule=rule_id, reason=desc)

        # 4. Standard Prompt Injections
        for rule_id, pat, desc in INJECTION_RULES:
            if pat.search(text):
                return Assessment(verdict='block', confidence=0.95, rule=rule_id, reason=desc)

        # 5. Exfiltration Compound (verb + credentials)
        if EXFIL_VERBS.search(text) and CRED_OBJECTS.search(text):
            return Assessment(
                verdict='block',
                confidence=0.90,
                rule='exfil:credentials',
                reason='Imperative verb requesting credentials/secrets'
            )

    return Assessment(verdict='allow', confidence=0.99, rule='none', reason=None)


# -------------------------------------------------------------------------
# DLP & Secret Masking Rules
# -------------------------------------------------------------------------
SECRET_PATTERNS: List[Tuple[str, re.Pattern, str]] = [
    ("secret:private_key", re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----'), "[REDACTED_PRIVATE_KEY]"),
    ("secret:anthropic_key", re.compile(r'\b(sk-ant-[A-Za-z0-9_-]{30,})\b'), "[REDACTED_ANTHROPIC_KEY]"),
    ("secret:openai_key", re.compile(r'\b(sk-(?!ant-)(?:proj-|svcacct-|none-)?[A-Za-z0-9_-]{28,})\b'), "[REDACTED_OPENAI_KEY]"),
    ("secret:aws_access_key", re.compile(r'\b(AKIA[0-9A-Z]{16})\b'), "[REDACTED_AWS_KEY]"),
    ("secret:aws_secret_key", re.compile(r'(?i)\b((?:aws_secret_access_key|aws_secret|aws_key)\s*[:=]\s*[\'"]?)([A-Za-z0-9/+=]{40})([\'"]?)'), r'\1[REDACTED_AWS_SECRET]\3'),
    ("secret:github_token", re.compile(r'\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,40}|github_pat_[A-Za-z0-9_]{82})\b'), "[REDACTED_GITHUB_TOKEN]"),
    ("secret:db_url_password", re.compile(r'((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^:\s\/]+:)([^@\s\/]+)(@)', re.IGNORECASE), r'\1[REDACTED_DB_PASSWORD]\3'),
    ("secret:jwt_token", re.compile(r'\b(eyJ[A-Za-z0-9-_=]{10,}\.eyJ[A-Za-z0-9-_=]{10,}\.[A-Za-z0-9-_.+/=]{10,})\b'), "[REDACTED_JWT]"),
    ("secret:env_credential", re.compile(r'(?i)\b((?:AWS_SECRET_ACCESS_KEY|SECRET_KEY|API_KEY|AUTH_TOKEN|PRIVATE_KEY|DATABASE_PASSWORD)\s*[:=]\s*[\'"]?)([^\s\'"]{12,})([\'"]?)'), r'\1[REDACTED_SECRET]\3'),
]

def redact_secrets(text: str) -> Tuple[str, List[Dict[str, Any]]]:
    """
    Scans a text for sensitive credentials (API keys, private keys, passwords)
    and redacts them in place. Returns (redacted_text, detected_secrets_list).
    """
    if not isinstance(text, str) or not text:
        return text, []

    redacted = text
    detections: List[Dict[str, Any]] = []

    for rule_id, pattern, replacement in SECRET_PATTERNS:
        matches = list(pattern.finditer(redacted))
        if matches:
            for m in matches:
                detections.append({
                    "rule": rule_id,
                    "start": m.start(),
                    "end": m.end(),
                })
            redacted = pattern.sub(replacement, redacted)

    return redacted, detections

def sanitize_tool_result(
    tool_or_result: Any,
    content: Optional[Any] = None,
    mask_secrets: bool = True
) -> Any:
    """
    Sanitizes tool output to prevent prompt injection and credential leakage.
    Can be called as:
      1) sanitize_tool_result(data) -> returns (clean_data, detections)
      2) sanitize_tool_result(tool_name, content, mask_secrets=True) -> returns dict with
         {tool_name, safe_to_ingest, assessment, secrets_redacted, sanitized_content}
    """
    if content is not None:
        tool_name = str(tool_or_result)
        text_content = content if isinstance(content, str) else str(content)
        assessment = evaluate(text_content)
        is_block = not assessment.allowed

        if is_block:
            sanitized = f"[REDACTED BY ZN-GATE: Malicious prompt injection payload detected in {tool_name} output ({assessment.reason or assessment.rule})]"
            secrets_redacted = 0
        else:
            if mask_secrets:
                sanitized, det = redact_secrets(text_content)
                secrets_redacted = len(det)
            else:
                sanitized = text_content
                secrets_redacted = 0

        return {
            "tool_name": tool_name,
            "safe_to_ingest": not is_block,
            "assessment": assessment,
            "secrets_redacted": secrets_redacted,
            "sanitized_content": sanitized,
        }

    # Deep data structure sanitization
    detections: List[Dict[str, Any]] = []

    def _sanitize(val: Any) -> Any:
        if isinstance(val, str):
            clean_str, det = redact_secrets(val)
            if det:
                detections.extend(det)
            return clean_str
        elif isinstance(val, dict):
            return {k: _sanitize(v) for k, v in val.items()}
        elif isinstance(val, list):
            return [_sanitize(v) for v in val]
        elif isinstance(val, tuple):
            return tuple(_sanitize(v) for v in val)
        return val

    sanitized = _sanitize(tool_or_result)
    return sanitized, detections



_EVAL_CACHE_MAX = 2048
_eval_cache = {}
_eval_cache_ver = RULES_VERSION


def evaluate(input_text: str) -> Assessment:
    """Cached entry point: LRU(2048) keyed on raw input, version-guarded."""
    global _eval_cache_ver
    if not isinstance(input_text, str):
        return _evaluate_uncached(input_text)
    if RULES_VERSION != _eval_cache_ver:
        _eval_cache.clear()
        _eval_cache_ver = RULES_VERSION
    hit = _eval_cache.get(input_text)
    if hit is not None:
        _eval_cache[input_text] = _eval_cache.pop(input_text)
        return Assessment(*hit)
    res = _evaluate_uncached(input_text)
    _eval_cache[input_text] = (res.verdict, res.confidence, res.rule,
                               res.reason, res.engine, res.rules_version)
    if len(_eval_cache) > _EVAL_CACHE_MAX:
        _eval_cache.pop(next(iter(_eval_cache)))
    return res
