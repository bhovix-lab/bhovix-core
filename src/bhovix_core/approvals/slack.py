"""Slack request verification (signing secret, v0 HMAC) and decision parsing.

The approver's identity is taken only from a request whose signature verified, never from a field a caller
supplies. Sending through Slack waits for the owner's yes.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Mapping
from urllib.parse import parse_qs

from bhovix_core.models import ApprovalDecision

MAX_AGE_S = 300


def verify(headers: Mapping[str, str], body: bytes, now_ts: float, signing_secret: str) -> bool:
    """True only for a correctly signed request no older than 5 minutes, with a non-empty secret."""
    if not signing_secret:
        return False
    h = {k.lower(): v for k, v in headers.items()}
    ts, sig = h.get("x-slack-request-timestamp", ""), h.get("x-slack-signature", "")
    if not (ts.isascii() and ts.isdigit()) or abs(now_ts - int(ts)) > MAX_AGE_S:
        return False
    if not (sig.isascii() and sig.startswith("v0=")):
        return False
    base = b"v0:" + ts.encode() + b":" + body
    want = "v0=" + hmac.new(signing_secret.encode(), base, hashlib.sha256).hexdigest()
    return hmac.compare_digest(want, sig)


def parse_decision(
    headers: Mapping[str, str], body: bytes, now_ts: float, signing_secret: str
) -> ApprovalDecision | None:
    """A Slack interactive payload -> ApprovalDecision, or None if the signature does not verify.

    The button value carries ``approval_id|plan_hash|step|approve|reject``; the approver is the verified Slack
    user id (``slack:<id>``), which principals.yaml maps to people.
    """
    if not verify(headers, body, now_ts, signing_secret):
        return None
    try:
        payload = json.loads(parse_qs(body.decode("utf-8"))["payload"][0])
        action = payload["actions"][0]
        approval_id, plan_hash, step, decision = action["value"].split("|")
        return ApprovalDecision(
            approval_id=approval_id,
            plan_hash=plan_hash,
            step=int(step),
            decision=decision,
            approver_id=f"slack:{payload['user']['id']}",
            channel="slack",
        )
    except (KeyError, IndexError, ValueError, TypeError):
        return None
