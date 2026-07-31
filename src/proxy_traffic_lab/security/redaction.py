from __future__ import annotations

import hashlib
import re

SENSITIVE_PATTERNS = (
    re.compile(r"(?i)(password|passwd|token|secret|private[_-]?key)\s*[=:]\s*\S+"),
    re.compile(
        r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-"
        r"[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b"
    ),
)


def stable_hash(value: str) -> str:
    return f"sha256:{hashlib.sha256(value.encode('utf-8')).hexdigest()}"


def redact(text: str) -> str:
    redacted = text
    for pattern in SENSITIVE_PATTERNS:
        redacted = pattern.sub("[REDACTED]", redacted)
    return redacted

