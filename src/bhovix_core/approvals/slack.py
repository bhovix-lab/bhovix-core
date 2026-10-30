"""Slack request verification (signing secret, v0 HMAC). Sending through Slack waits for the owner's yes."""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Mapping

MAX_AGE_S = 300


def verify(headers: Mapping[str, str], body: bytes, now_ts: float, signing_secret: str) -> bool:
    """True only for a correctly signed request no older than 5 minutes."""
    h = {k.lower(): v for k, v in headers.items()}
    ts, sig = h.get("x-slack-request-timestamp", ""), h.get("x-slack-signature", "")
    if not ts.isdigit() or abs(now_ts - int(ts)) > MAX_AGE_S or not sig.startswith("v0="):
        return False
    base = b"v0:" + ts.encode() + b":" + body
    want = "v0=" + hmac.new(signing_secret.encode(), base, hashlib.sha256).hexdigest()
    return hmac.compare_digest(want, sig)
