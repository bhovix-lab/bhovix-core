"""Data shapes shared by every module, plus ids and canonical hashing.

Every persisted shape carries ``schema_version``. Money is ``Decimal`` (never float).
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime
from decimal import Decimal
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


def now() -> datetime:
    return datetime.now(UTC)


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex}"


def _no_floats(obj: Any, path: str = "$") -> None:
    if isinstance(obj, float):
        raise ValueError(f"float at {path}: use a decimal string")  # noqa: TRY004 - a bad value
    if isinstance(obj, dict):
        for k, v in obj.items():
            _no_floats(v, f"{path}.{k}")
    elif isinstance(obj, list | tuple):
        for i, v in enumerate(obj):
            _no_floats(v, f"{path}[{i}]")


def canonical_json(obj: Any) -> str:
    """Key-order independent JSON; refuses floats so money cannot drift."""
    if isinstance(obj, BaseModel):
        obj = obj.model_dump(mode="json")
    _no_floats(obj)
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(obj: Any) -> str:
    return hashlib.sha256(canonical_json(obj).encode("utf-8")).hexdigest()


class Shape(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: int = 1


class RunState(StrEnum):
    RECEIVED = "RECEIVED"
    WORKING = "WORKING"
    NO_ACTION = "NO_ACTION"
    PLAN_READY = "PLAN_READY"
    NEEDS_PERSON = "NEEDS_PERSON"
    DENIED = "DENIED"
    WAITING_FOR_APPROVAL = "WAITING_FOR_APPROVAL"
    EXECUTING = "EXECUTING"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    VERIFYING = "VERIFYING"
    SUCCEEDED = "SUCCEEDED"
    ROLLED_BACK = "ROLLED_BACK"
    STOPPED = "STOPPED"


RiskClass = Literal["read_only", "reversible", "sign_off"]
Outcome = Literal["allow", "needs_approval", "deny"]
ApprovalStatus = Literal["PENDING", "APPROVED", "REJECTED", "EXPIRED"]


class Run(Shape):
    run_id: str = Field(default_factory=lambda: new_id("run"))
    agent_id: str
    principal_id: str
    trigger_kind: Literal["event", "schedule", "user"]
    trigger_ref: str
    state: RunState = RunState.RECEIVED
    reason_code: str | None = None
    cost_usd: Decimal = Decimal(0)
    created_at: datetime = Field(default_factory=now)
    updated_at: datetime = Field(default_factory=now)


class Target(BaseModel):
    model_config = ConfigDict(extra="forbid")
    system: str
    ref: str | None = None


class Plan(Shape):
    plan_id: str = Field(default_factory=lambda: new_id("pln"))
    run_id: str
    agent_id: str
    action_id: str
    action_version: int
    risk_class: RiskClass
    inputs: dict[str, Any]
    target: Target
    idempotency_key: str
    expected_outcome: str
    created_at: datetime = Field(default_factory=now)

    @field_validator("created_at")
    @classmethod
    def _utc(cls, value: datetime) -> datetime:
        """The hash covers created_at: one instant must serialise one way, whatever store returned it."""
        if value.utcoffset() is None:
            raise ValueError("created_at must be timezone-aware")
        return value.astimezone(UTC)

    def hash(self) -> str:
        # Normalised here too: model_copy(update=...) and attribute assignment skip the validator.
        return sha256_hex(self.model_copy(update={"created_at": self._utc(self.created_at)}))


class GateDecision(Shape):
    run_id: str
    plan_hash: str
    outcome: Outcome
    rule_id: str
    ts: datetime = Field(default_factory=now)


class ChainStep(BaseModel):
    model_config = ConfigDict(extra="forbid")
    approver_ids: list[str]
    timeout_s: int


class ApprovalRequest(Shape):
    approval_id: str = Field(default_factory=lambda: new_id("apr"))
    run_id: str
    plan_hash: str
    risk_class: RiskClass
    chain_id: str
    steps: list[ChainStep]
    current_step: int = 0
    status: ApprovalStatus = "PENDING"
    step_expires_at: datetime
    requested_by: str
    summary: str
    created_at: datetime = Field(default_factory=now)
    sent_at: datetime | None = None  # None: the channel send failed; tick resends
    channel_ref: str | None = None  # the channel's message id (Slack: the message ts), for updates


class ApprovalDecision(Shape):
    approval_id: str
    plan_hash: str
    step: int
    decision: Literal["approve", "reject"]
    approver_id: str
    channel: str
    reason: str = ""
    decided_at: datetime = Field(default_factory=now)


class AuditEvent(Shape):
    """Hashes and codes only: never payload text."""

    event_id: str = Field(default_factory=lambda: new_id("evt"))
    ts: datetime = Field(default_factory=now)
    run_id: str
    domain: str
    operation: str
    principal: str
    source: str
    object_ref: str | None = None
    inputs_hash: str | None = None
    decision: str | None = None
    rule_id: str | None = None
    result: str | None = None
    error_code: str | None = None


class DeadLetter(Shape):
    run_id: str
    reason: str
    errors: list[str]
    ts: datetime = Field(default_factory=now)


class TickState(BaseModel):
    """One tick step's last run (table tick_state)."""

    model_config = ConfigDict(extra="forbid")
    step: str
    last_run_at: datetime
    last_ok_at: datetime | None = None
    last_error: str | None = None


class KillSwitch(Shape):
    on: bool = False
    by: str | None = None
    ts: datetime = Field(default_factory=now)


class GateRun(Shape):
    agent_id: str
    model_id: str
    prompt_sha256: str
    config_hash: str
    golden_sha256: str
    n: int
    passed: int
    pass_rate: float
    threshold: float
    green: bool
    ts: datetime = Field(default_factory=now)


class ToolCall(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    input: dict[str, Any]


class Reply(Shape):
    text: str = ""
    tool_calls: list[ToolCall] = []
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: Decimal = Decimal(0)
    model_id: str
    stop_reason: str = "end_turn"
    latency_ms: int = 0


class Verdict(Shape):
    flagged: bool
    score: float = Field(ge=0.0, le=1.0)
    backend: str
    reason_code: str | None = None
    cost_usd: Decimal = Decimal(
        0
    )  # a model-backed detector's call (llm_judge), charged by the caller


class RunResult(Shape):
    outcome: Literal["succeeded", "failed", "unknown"]
    external_ref: str | None = None
    error_code: str | None = None
    retryable: bool = False
