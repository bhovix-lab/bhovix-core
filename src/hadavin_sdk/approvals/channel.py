"""Approval channel Protocol and the fake channel. Channel text is template-built, redacted and link-free."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol

from hadavin_sdk.approvals.gate import sanitise_text
from hadavin_sdk.guard.redact import redact
from hadavin_sdk.models import ApprovalDecision, ApprovalRequest


def clean(text: str) -> str:
    """Redact, then WARDEN's G3 cleaning (`gate.sanitise_text`): no link, image, HTML, mention, control
    character or forged markdown structure survives in text a person acts on."""
    return sanitise_text(redact(text).text)


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
    """Records what would be sent. Callbacks are verified exactly like Slack's (v0 HMAC) with a test secret;
    with no secret every callback is refused."""

    name = "fake"

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
        from hadavin_sdk.approvals.slack import parse_decision

        d = parse_decision(headers, body, now_ts, self._secret)
        return None if d is None else d.model_copy(update={"channel": self.name})
