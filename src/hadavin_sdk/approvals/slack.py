"""Slack request verification and decision parsing: the shared ``hmac_v0`` scheme under Slack's headers.

The approver's identity is taken only from a request whose signature verified, never from a field a caller
supplies.
"""

from __future__ import annotations

from collections.abc import Mapping

from hadavin_sdk.approvals import hmac_v0
from hadavin_sdk.models import ApprovalDecision

MAX_AGE_S = hmac_v0.MAX_AGE_S
HEADER_PREFIX = "X-Slack"


def verify(headers: Mapping[str, str], body: bytes, now_ts: float, signing_secret: str) -> bool:
    """True only for a correctly signed Slack request no older than 5 minutes, with a non-empty secret."""
    return hmac_v0.verify(headers, body, now_ts, signing_secret, HEADER_PREFIX)


def parse_decision(
    headers: Mapping[str, str],
    body: bytes,
    now_ts: float,
    signing_secret: str,
    channel: str = "slack",
) -> ApprovalDecision | None:
    """A Slack interactive payload -> ApprovalDecision (approver ``<channel>:<Slack user id>``), or None."""
    return hmac_v0.parse_button(
        headers, body, now_ts, signing_secret, prefix=HEADER_PREFIX, channel=channel
    )
