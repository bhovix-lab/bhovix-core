"""Approval channel Protocol and the fake channel. Channel text is template-built, redacted and link-free."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol

from hadavin_sdk.approvals import hmac_v0
from hadavin_sdk.approvals.gate import sanitise_text
from hadavin_sdk.guard.redact import redact
from hadavin_sdk.models import ApprovalDecision, ApprovalRequest


def clean(text: str) -> str:
    """Redact, then WARDEN's G3 cleaning (`gate.sanitise_text`): no link, image, HTML, mention, control
    character or forged markdown structure survives in text a person acts on."""
    first = redact(text)
    # Sanitising removes invisible and control characters and tags, which can join a split secret
    # (`AKIA` + zero-width space + `IOSF...`): redact the cleaned text again (WARDEN's G5 re-scan), in the
    # same placeholder namespace.
    return redact(sanitise_text(first.text), mapping=first.mapping).text


class Channel(Protocol):
    name: str

    def send(self, req: ApprovalRequest, approver_ids: list[str]) -> str: ...
    def update(self, req: ApprovalRequest) -> None: ...
    def notify(self, principal_id: str, text: str) -> None: ...

    def parse_decision(
        self, headers: Mapping[str, str], body: bytes, now_ts: float
    ) -> ApprovalDecision | None:
        """Verify the callback and return the decision with the approver taken from the verified request."""
        ...


class FakeChannel:
    """Records what would be sent. Callbacks are verified with the shared ``hmac_v0`` scheme under its own
    ``X-Hadavin-*`` headers and a test secret (with no secret every callback is refused); approvers are
    ``fake:<id>``."""

    name = "fake"
    header_prefix = "X-Hadavin"  # the shared hmac_v0 scheme under neutral header names

    def __init__(self, signing_secret: str = "") -> None:
        self._secret = signing_secret
        self.sent: list[tuple[str, str, list[str]]] = []
        self.updates: list[tuple[str, str]] = []
        self.notices: list[tuple[str, str]] = []

    def send(self, req: ApprovalRequest, approver_ids: list[str]) -> str:
        self.sent.append((req.approval_id, clean(req.summary), list(approver_ids)))
        return f"fake-{len(self.sent)}"

    def update(self, req: ApprovalRequest) -> None:
        self.updates.append((req.approval_id, req.status))

    def notify(self, principal_id: str, text: str) -> None:
        self.notices.append((principal_id, clean(text)))

    def parse_decision(
        self, headers: Mapping[str, str], body: bytes, now_ts: float
    ) -> ApprovalDecision | None:
        return hmac_v0.parse_button(
            headers, body, now_ts, self._secret, prefix=self.header_prefix, channel=self.name
        )
