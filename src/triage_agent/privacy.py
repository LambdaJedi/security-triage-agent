"""Privacy helpers for secure data handling.

Findings can contain credentials, personal data, or internal addresses.
Before anything is written to the database, free text is passed through
``redact`` so those values never reach disk. A SHA-256 fingerprint of the
original text is kept instead, so duplicate submissions can still be
detected without storing the sensitive content.
"""

import hashlib
import re
from typing import Any


# Order matters: more specific patterns run before general ones.
_PATTERNS: list[tuple[str, re.Pattern]] = [
    (
        "PRIVATE_KEY",
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
            re.DOTALL,
        ),
    ),
    (
        "JWT",
        re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b"),
    ),
    (
        "AWS_ACCESS_KEY",
        re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    ),
    (
        "API_KEY",
        re.compile(r"\b(?:sk|pk|ghp|gho|xox[abp])[-_][A-Za-z0-9_-]{16,}\b"),
    ),
    (
        "BEARER_TOKEN",
        re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{16,}"),
    ),
    (
        "CREDENTIAL",
        re.compile(
            r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|token)\b"
            r"(\s*[:=]\s*)(\S+)"
        ),
    ),
    (
        "EMAIL",
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    ),
    (
        "IPV4",
        re.compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
        ),
    ),
    (
        "PHONE",
        re.compile(r"(?<!\w)\+?\d{1,3}[\s-]?\(?\d{2,3}\)?[\s-]?\d{3}[\s-]?\d{3,4}(?!\w)"),
    ),
]


def redact(text: str) -> tuple[str, dict[str, int]]:
    """Replace sensitive values with ``[REDACTED:<TYPE>]`` markers.

    Returns the redacted text and a count of what was removed per type.
    Redaction is deliberately conservative: it favours removing too much
    over leaking a credential.
    """

    counts: dict[str, int] = {}

    for label, pattern in _PATTERNS:

        if label == "CREDENTIAL":
            # Keep the key name and separator, hide only the value.
            def _sub(match, _label=label):
                counts[_label] = counts.get(_label, 0) + 1
                return f"{match.group(1)}{match.group(2)}[REDACTED:{_label}]"

            text = pattern.sub(_sub, text)
            continue

        text, n = pattern.subn(f"[REDACTED:{label}]", text)

        if n:
            counts[label] = counts.get(label, 0) + n

    return text, counts


def fingerprint(text: str) -> str:
    """Return a SHA-256 hex digest of the whitespace-normalised text.

    Used to detect duplicate findings without storing the original text.
    """

    normalised = " ".join(text.split()).lower()

    return hashlib.sha256(normalised.encode("utf-8")).hexdigest()


def redact_structure(value: Any) -> Any:
    """Redact every string inside nested dicts and lists.

    Redacting the values (not the serialised JSON text) keeps the
    document valid: a pattern can never swallow a quote or comma.
    """

    if isinstance(value, str):
        return redact(value)[0]

    if isinstance(value, dict):
        return {key: redact_structure(item) for key, item in value.items()}

    if isinstance(value, (list, tuple)):
        return [redact_structure(item) for item in value]

    return value
