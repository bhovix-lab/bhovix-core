"""Redaction for logs, audit and channel text. Documents go to the model unredacted (extraction needs them).

Copied then edited from WARDEN ``redaction.py``: the secret and PII patterns the core's text paths meet, plus bank
patterns (AU BSB, UK sort code, CA transit). Order matters: specific patterns run before broad ones.
ponytail: subset of WARDEN's 611-line table; add a WARDEN pattern when a client's data shows that shape.
"""

from __future__ import annotations

import re

_KEY_PREFIXES = (
    r"sk-ant-|sk-|sk_live_|sk_test_|rk_live_|pk_live_|github_pat_|ghp_|gho_|ghu_|ghs_|ghr_|AKIA|ASIA|"
    r"xox[baprs]-|glpat-|AIza|npm_|hf_|re_"
)

PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "PRIVKEY",
        re.compile(
            r"-----BEGIN[A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?(?:-----END[A-Z0-9 ]*PRIVATE KEY-----|\Z)"
        ),
    ),
    ("JWT", re.compile(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*\.[A-Za-z0-9_\-]+")),
    ("APIKEY", re.compile(r"\b(?:" + _KEY_PREFIXES + r")[A-Za-z0-9_\-]{8,}\b")),
    ("EMAIL", re.compile(r"\b[A-Za-z0-9._+\-]+(?:@|%40)[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")),
    ("IBAN", re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b")),
    ("CARD", re.compile(r"\b(?:\d[ -]?){12,18}\d\b")),
    # Bank routing numbers, each only next to its own label so an ordinary number is not masked.
    ("BSB", re.compile(r"(?i)\bBSB\b\W{0,3}(\d{3}-?\d{3})\b")),
    ("SORTCODE", re.compile(r"(?i)\bsort\s*code\b\W{0,3}(\d{2}-\d{2}-\d{2}|\d{6})\b")),
    ("TRANSIT", re.compile(r"(?i)\btransit\b(?:\s*(?:no\.?|number|#))?\W{0,3}(\d{5}-?\d{3})\b")),
    ("ACCOUNT", re.compile(r"(?i)\b(?:account|acct)\s*(?:no\.?|number|#)?\W{0,3}(\d{6,12})\b")),
    ("PHONE", re.compile(r"(?<![\w.\-])\+?\d(?:[\d \-]){8,14}\d(?![\w.])")),
    (
        "SECRET",
        re.compile(
            r"(?i)[\w.\-]{0,20}(?:password|passwd|secret|token|api[_-]?key|credential)[\w.\-]{0,20}"
            r"\s*[:=]\s*[\"']?([^\s\"']{4,})"
        ),
    ),
]


def redact(text: str) -> tuple[str, list[str]]:
    """Returns (redacted text, kinds found). A pattern with a group masks only the group."""
    kinds: list[str] = []
    for kind, rx in PATTERNS:

        def sub(m: re.Match[str], kind: str = kind) -> str:
            if kind not in kinds:
                kinds.append(kind)
            if m.groups() and m.group(1):
                whole, part = m.group(0), m.group(1)
                return whole.replace(part, f"<{kind}>")
            return f"<{kind}>"

        text = rx.sub(sub, text)
    return text, kinds
