"""Store Protocol: Hadavin-owned rows. ``memory`` now, ``postgres`` when Portal v0 or S11 needs it."""

from __future__ import annotations

from datetime import date, datetime
from decimal import Decimal
from typing import Protocol

from hadavin_sdk.errors import ConfigError
from hadavin_sdk.models import (
    ApprovalDecision,
    ApprovalRequest,
    ApprovalStatus,
    DeadLetter,
    GateDecision,
    KillSwitch,
    Plan,
    Run,
    RunState,
    TickState,
)


class StaleState(RuntimeError):
    """Compare-and-set failed: the row changed since it was read."""


class StoreUnavailable(ConfigError):
    """The store cannot be reached (`tick` exits 3; nothing was changed)."""


class NotFound(KeyError):
    pass


class Store(Protocol):
    def create_run(self, run: Run) -> None: ...
    def get_run(self, run_id: str) -> Run: ...
    def transition(
        self, run_id: str, expected: RunState, new: RunState, reason_code: str | None = None
    ) -> Run: ...
    def add_cost(self, run_id: str, usd: Decimal) -> None:
        """Raises NotFound for an unknown run."""
        ...

    def touch(self, run_id: str) -> None:
        """Heartbeat only: set `updated_at` to now; never checks or changes the state (tick's stuck-run
        rule). `transition` is the only compare-and-set."""
        ...

    def list_runs(self, state: RunState, updated_before: datetime, limit: int = 100) -> list[Run]:
        """Runs in `state` not updated since `updated_before`, oldest first, at most `limit`."""
        ...

    def save_plan(self, plan: Plan) -> None: ...
    def get_plan(self, run_id: str) -> Plan: ...

    def save_gate_decision(self, decision: GateDecision) -> None:
        """Once per run (append-only): a second one raises StaleState."""
        ...

    def get_gate_decision(self, run_id: str) -> GateDecision: ...

    def save_approval_request(self, req: ApprovalRequest) -> None: ...
    def get_approval_request(self, approval_id: str) -> ApprovalRequest: ...
    def update_approval_request(
        self, req: ApprovalRequest, expected_status: str, expected_step: int
    ) -> None: ...
    def list_due_approvals(self, now: datetime) -> list[ApprovalRequest]: ...
    def save_approval_decision(self, decision: ApprovalDecision) -> None:
        """One per (approval_id, step): a second one raises StaleState."""
        ...

    def get_approval_decision(self, approval_id: str) -> ApprovalDecision | None:
        """The latest accepted decision for a request, or None (tick reconcile after a crash)."""
        ...

    def list_approvals(self, statuses: set[ApprovalStatus]) -> list[ApprovalRequest]: ...

    def add_dead_letter(self, dl: DeadLetter) -> None: ...
    def list_dead_letters(self, run_id: str) -> list[DeadLetter]: ...

    def add_spend(self, agent_id: str, day: date, usd: Decimal) -> tuple[Decimal, Decimal]: ...
    def spend_totals(self, agent_id: str, day: date) -> tuple[Decimal, Decimal]:
        """(day, month) totals; a read with no write."""
        ...

    def get_kill_switch(self) -> KillSwitch:
        """A missing or unreadable switch row reads as ON (fail closed)."""
        ...

    def set_kill_switch(self, ks: KillSwitch) -> None: ...
    def get_tick_state(self, step: str) -> TickState | None: ...
    def save_tick_state(self, state: TickState) -> None: ...
