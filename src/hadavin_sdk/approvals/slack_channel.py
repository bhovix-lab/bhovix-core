"""Slack approval channel: `chat.postMessage` with Approve / Reject buttons, `chat.update` when decided.

Each client runs its OWN internal Slack app, created in its workspace from `docs/slack-app-manifest.yaml`
(scope `chat:write` only); the tokens stay in the client's secrets backend. Hadavin never ships one shared,
distributed app (Slack rate-limits non-Marketplace distributed apps far more tightly; see docs/slack-app.md).

Stdlib HTTP only, no redirects. Text a person acts on is template-built and `clean()`ed, sent as plain_text so
Slack renders no markdown, links or mentions from it. Clicks come back through the receiver (`receiver.py`),
verified with the signing secret (`slack.parse_decision`); the approver is the verified Slack user.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from hadavin_sdk.approvals import slack
from hadavin_sdk.approvals.channel import clean
from hadavin_sdk.errors import ConfigError
from hadavin_sdk.llm.common import post_json
from hadavin_sdk.models import ApprovalDecision, ApprovalRequest

API = "https://slack.com/api"


class SlackError(RuntimeError):
    """Slack answered `ok: false`; the message is Slack's error code only (never the request)."""


class SlackChannel:
    name = "slack"

    def __init__(
        self,
        channel_id: str,
        bot_token: str,
        signing_secret: str,
        *,
        api_base: str = API,
        timeout_s: float = 10.0,
    ) -> None:
        self.channel_id, self._token, self._secret = channel_id, bot_token, signing_secret
        self.api_base, self.timeout_s = api_base.rstrip("/"), timeout_s

    def _call(self, method: str, body: dict[str, Any]) -> dict[str, Any]:
        reply = post_json(
            f"{self.api_base}/{method}",
            body,
            {"Authorization": f"Bearer {self._token}"},
            self.timeout_s,
        )
        if not isinstance(reply, dict) or not reply.get("ok"):
            code = reply.get("error") if isinstance(reply, dict) else "bad_reply"
            raise SlackError(f"{method}: {code}")
        return reply

    def _who(self, approver_id: str) -> str:
        """A mention for this channel's own users (`<name>:<id>`); any other principal id as written."""
        kind, _, ident = approver_id.partition(":")
        return f"<@{ident}>" if kind == self.name and ident.isalnum() else approver_id

    def _blocks(self, req: ApprovalRequest, approver_ids: list[str] | None) -> list[dict[str, Any]]:
        step = f"Step {req.current_step + 1} of {len(req.steps)}"
        blocks: list[dict[str, Any]] = [
            {"type": "section", "text": {"type": "plain_text", "text": clean(req.summary)[:2900]}},
        ]
        if approver_ids is None:  # decided or expired: the buttons go
            blocks.append(
                {"type": "context", "elements": [{"type": "plain_text", "text": f"{req.status}."}]}
            )
            return blocks
        who = ", ".join(self._who(a) for a in approver_ids)
        blocks.append(
            {
                "type": "context",
                "elements": [{"type": "mrkdwn", "text": f"{step}. Approvers: {who}"}],
            }
        )
        value = f"{req.approval_id}|{req.plan_hash}|{req.current_step}"
        blocks.append(
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "style": "primary",
                        "text": {"type": "plain_text", "text": "Approve"},
                        "action_id": "approve",
                        "value": f"{value}|approve",
                    },
                    {
                        "type": "button",
                        "style": "danger",
                        "text": {"type": "plain_text", "text": "Reject"},
                        "action_id": "reject",
                        "value": f"{value}|reject",
                    },
                ],
            }
        )
        return blocks

    def send(self, req: ApprovalRequest, approver_ids: list[str]) -> str:
        reply = self._call(
            "chat.postMessage",
            {
                "channel": self.channel_id,
                "text": "Approval needed",  # notification fallback; the content is in the blocks
                "blocks": self._blocks(req, approver_ids),
                "unfurl_links": False,
                "unfurl_media": False,
            },
        )
        # chat.update needs the channel *id*; the configured value may be a name, so keep Slack's answer.
        return f"{reply.get('channel') or self.channel_id}|{reply['ts']}"

    def update(self, req: ApprovalRequest) -> None:
        if not req.channel_ref:  # never sent: nothing to update
            return
        channel, _, ts = req.channel_ref.rpartition("|")
        self._call(
            "chat.update",
            {
                "channel": channel or self.channel_id,
                "ts": ts,
                "text": f"Approval {req.status.lower()}",
                "blocks": self._blocks(req, None),
            },
        )

    def notify(self, principal_id: str, text: str) -> None:
        self._call(
            "chat.postMessage",
            {"channel": self.channel_id, "text": f"{self._who(principal_id)}: {clean(text)}"},
        )

    def parse_decision(
        self, headers: Mapping[str, str], body: bytes, now_ts: float
    ) -> ApprovalDecision | None:
        return slack.parse_decision(headers, body, now_ts, self._secret, self.name)


def build(settings, deps) -> SlackChannel:
    """Table factory: both Slack credentials are platform secrets named in the settings."""
    if not settings.api_base.startswith("https://"):
        raise ConfigError("channel slack: api_base must be https")
    return SlackChannel(
        settings.channel_id,
        deps.resolve(settings.bot_token_secret_name),
        deps.resolve(settings.signing_secret_name),
        api_base=settings.api_base,
        timeout_s=settings.timeout_s,
    )
