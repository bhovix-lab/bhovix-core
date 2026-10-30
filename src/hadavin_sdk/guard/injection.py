"""Injection detector: a tripwire, never a gate that clears text as safe. Fail closed.

The regex detector rewrites WARDEN's tripwire + STEER idea for documents: phrases that try to steer the model.
"""

from __future__ import annotations

import logging
import re
from decimal import Decimal
from typing import Protocol

from hadavin_sdk.models import Verdict

_LOG = logging.getLogger("hadavin_sdk.guard")


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


class AnyOf:
    """A detector list (design 4.3): every entry runs, and any flag flags the run. The combined verdict has the
    max score, the names that flagged joined by `+`, the first flag's reason and the summed cost. One entry's
    error is that entry's flag (guard_unavailable); the others still run."""

    def __init__(self, detectors: list[Detector]) -> None:
        self.detectors = detectors

    def check(self, text: str, source: str) -> Verdict:
        verdicts = [injection_check(d, text, source) for d in self.detectors]
        flagged = [v for v in verdicts if v.flagged]
        return Verdict(
            flagged=bool(flagged),
            score=max(v.score for v in verdicts),
            backend="+".join(v.backend for v in flagged or verdicts),
            reason_code=flagged[0].reason_code if flagged else None,
            cost_usd=sum((v.cost_usd for v in verdicts), Decimal(0)),
        )


def combine(detectors: list[Detector]) -> Detector:
    return detectors[0] if len(detectors) == 1 else AnyOf(detectors)


def injection_check(detector: Detector, text: str, source: str) -> Verdict:
    """Any detector error is a flag (guard_unavailable), never a pass."""
    try:
        return detector.check(text, source)
    except Exception as exc:  # noqa: BLE001 - fail closed on anything
        # The cause is logged (class and message, never the text checked) so a broken detector is
        # diagnosable, e.g. a custom detector returning a score outside 0..1.
        _LOG.warning(
            "detector %s failed, run flagged: %s: %s",
            type(detector).__name__,
            type(exc).__name__,
            str(exc)[:300],
        )
        return Verdict(flagged=True, score=1.0, backend="error", reason_code="guard_unavailable")
