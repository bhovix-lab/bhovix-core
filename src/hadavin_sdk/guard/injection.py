"""Injection detector: a tripwire, never a gate that clears text as safe. Fail closed.

The regex detector rewrites WARDEN's tripwire + STEER idea for documents: phrases that try to steer the model.
"""

from __future__ import annotations

import re
from typing import Protocol

from hadavin_sdk.models import Verdict


class Detector(Protocol):
    def check(self, text: str, source: str) -> Verdict: ...


_PATTERNS = [
    r"\bignore\b.{0,40}\b(previous|prior|above|earlier|all)\b.{0,20}\b(instructions?|rules?|prompts?)\b",
    r"\bdisregard\b.{0,40}\b(instructions?|rules?|prompts?|above)\b",
    r"\bforget\b.{0,30}\b(instructions?|rules?|everything)\b",
    r"\b(system|developer)\s+prompt\b",
    r"\byou\s+are\s+now\b",
    r"\bnew\s+instructions?\s*:",
    r"\b(act|pretend)\s+as\b",
    r"\boverride\b.{0,30}\b(rules?|policy|safety|instructions?)\b",
]
_RX = re.compile("|".join(f"(?:{p})" for p in _PATTERNS), re.IGNORECASE | re.DOTALL)
_SQUASH = re.compile(r"[^a-z]")
_SQUASHED = ("ignorepreviousinstructions", "ignoreallpreviousinstructions", "disregardtheabove")


class RegexDetector:
    backend = "regex"

    def __init__(self, threshold: float) -> None:
        self.threshold = threshold

    def _score(self, text: str) -> float:
        if _RX.search(text):
            return 1.0
        squashed = _SQUASH.sub("", text.lower())
        return 1.0 if any(s in squashed for s in _SQUASHED) else 0.0

    def check(self, text: str, source: str) -> Verdict:
        score = self._score(text)
        flagged = score >= self.threshold
        return Verdict(
            flagged=flagged,
            score=score,
            backend=self.backend,
            reason_code="injection_suspected" if flagged else None,
        )


def injection_check(detector: Detector, text: str, source: str) -> Verdict:
    """Any detector error is a flag (guard_unavailable), never a pass."""
    try:
        return detector.check(text, source)
    except Exception:  # noqa: BLE001 - fail closed on anything
        return Verdict(flagged=True, score=1.0, backend="error", reason_code="guard_unavailable")
