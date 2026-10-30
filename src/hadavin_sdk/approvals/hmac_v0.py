"""HMAC-SHA256 "v0" request signing, shared by every channel that receives signed button callbacks.

``signature = "v0=" + hex(HMAC_SHA256(secret, "v0:{ts}:" + body))`` with a Unix-seconds timestamp header; a
request older than ``MAX_AGE_S`` is refused. Slack signs this way under ``X-Slack-*``; the fake channel and
later webhook channels use the same scheme under their own header prefix. The approver is taken only from a
request whose signature verified, and is named ``<channel>:<user id>``.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Mapping
from urllib.parse import parse_qs

from hadavin_sdk.models import ApprovalDecision

MAX_AGE_S = 300


def _names(prefix: str) -> tuple[str, str]:
    return f"{prefix}-Request-Timestamp".lower(), f"{prefix}-Signature".lower()


def _sig(body: bytes, ts: str, secret: str) -> str:
    base = b"v0:" + ts.encode() + b":" + body
    return "v0=" + hmac.new(secret.encode(), base, hashlib.sha256).hexdigest()


def sign(body: bytes, ts: int, secret: str, prefix: str) -> dict[str, str]:
    """The headers a sender attaches (tests and channels that relay callbacks)."""
    ts_name, sig_name = _names(prefix)
    return {ts_name: str(ts), sig_name: _sig(body, str(ts), secret)}


def verify(
    headers: Mapping[str, str], body: bytes, now_ts: float, secret: str, prefix: str
) -> bool:
    """True only for a correctly signed request no older than 5 minutes, with a non-empty secret."""
    if not secret:
        return False
    ts_name, sig_name = _names(prefix)
    h = {k.lower(): v for k, v in headers.items()}
    ts, sig = h.get(ts_name, ""), h.get(sig_name, "")
    # Unix seconds fit in 12 digits; a longer header would make int() raise past Python's digit limit.
    if not (ts.isascii() and ts.isdigit() and len(ts) <= 12) or abs(now_ts - int(ts)) > MAX_AGE_S:
        return False
    if not (sig.isascii() and sig.startswith("v0=")):
        return False
    return hmac.compare_digest(_sig(body, ts, secret), sig)


def parse_button(
    headers: Mapping[str, str],
    body: bytes,
    now_ts: float,
    secret: str,
    *,
    prefix: str,
    channel: str,
) -> ApprovalDecision | None:
    """A form-encoded ``payload`` (``user.id``, ``actions[0].value`` =
    ``approval_id|plan_hash|step|approve|reject``) -> ApprovalDecision, or None unless the signature verifies."""
    if not verify(headers, body, now_ts, secret, prefix):
        return None
    try:
        payload = json.loads(parse_qs(body.decode("utf-8"))["payload"][0])
        approval_id, plan_hash, step, decision = payload["actions"][0]["value"].split("|")
        return ApprovalDecision(
            approval_id=approval_id,
            plan_hash=plan_hash,
            step=int(step),
            decision=decision,
            approver_id=f"{channel}:{payload['user']['id']}",
            channel=channel,
        )
    except (KeyError, IndexError, ValueError, TypeError):
        return None
