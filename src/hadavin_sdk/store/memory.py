"""In-memory store: dicts behind one lock. Rows are lost on restart (stated; Postgres comes with its trigger)."""

from __future__ import annotations

import threading
from collections import defaultdict
from datetime import date, datetime
from decimal import Decimal

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
    now,
)
from hadavin_sdk.store.protocol import NotFound, StaleState


class MemoryStore:
    def __init__(self) -> None:
        # ponytail: one global lock; per-row locks only if a real backend ever needs throughput here.
        self._lock = threading.Lock()
        self._runs: dict[str, Run] = {}
        self._plans: dict[str, Plan] = {}
        self._gates: dict[str, GateDecision] = {}
        self._approvals: dict[str, ApprovalRequest] = {}
        self._decisions: list[ApprovalDecision] = []
        self._dead: dict[str, list[DeadLetter]] = defaultdict(list)
        self._spend: dict[tuple[str, date], Decimal] = defaultdict(Decimal)
        self._kill = KillSwitch()
        self._ticks: dict[str, TickState] = {}

    @staticmethod
    def _get(table: dict, key: str):
        try:
            return table[key].model_copy(deep=True)
        except KeyError:
            raise NotFound(key) from None

    def create_run(self, run: Run) -> None:
        with self._lock:
            if run.run_id in self._runs:
                raise StaleState(f"run exists: {run.run_id}")
            self._runs[run.run_id] = run.model_copy(deep=True)

    def get_run(self, run_id: str) -> Run:
        with self._lock:
            return self._get(self._runs, run_id)

    def transition(
        self, run_id: str, expected: RunState, new: RunState, reason_code: str | None = None
    ) -> Run:
        with self._lock:
            run = self._runs.get(run_id)
            if run is None:
                raise NotFound(run_id)
            if run.state != expected:
                raise StaleState(f"{run_id}: state is {run.state}, expected {expected}")
            run = run.model_copy(
                update={"state": new, "reason_code": reason_code, "updated_at": now()}
            )
            self._runs[run_id] = run
            return run.model_copy(deep=True)

    def add_cost(self, run_id: str, usd: Decimal) -> None:
        with self._lock:
            run = self._runs.get(run_id)
            if run is None:
                raise NotFound(run_id)
            self._runs[run_id] = run.model_copy(update={"cost_usd": run.cost_usd + usd})

    def touch(self, run_id: str) -> None:
        """Heartbeat only: moves `updated_at`, never checks or changes the state (`transition` is the only
        compare-and-set)."""
        with self._lock:
            run = self._runs.get(run_id)
            if run is None:
                raise NotFound(run_id)
            self._runs[run_id] = run.model_copy(update={"updated_at": now()})

    def list_runs(self, state: RunState, updated_before: datetime, limit: int = 100) -> list[Run]:
        """Oldest first, at most `limit`."""
        with self._lock:
            found = sorted(
                (
                    r
                    for r in self._runs.values()
                    if r.state == state and r.updated_at < updated_before
                ),
                key=lambda r: r.updated_at,
            )
            return [r.model_copy(deep=True) for r in found[:limit]]

    def save_plan(self, plan: Plan) -> None:
        with self._lock:
            self._plans[plan.run_id] = plan.model_copy(deep=True)

    def get_plan(self, run_id: str) -> Plan:
        with self._lock:
            return self._get(self._plans, run_id)

    def save_gate_decision(self, decision: GateDecision) -> None:
        with self._lock:
            if decision.run_id in self._gates:
                raise StaleState(f"gate decision exists: {decision.run_id}")
            self._gates[decision.run_id] = decision.model_copy(deep=True)

    def get_gate_decision(self, run_id: str) -> GateDecision:
        with self._lock:
            return self._get(self._gates, run_id)

    def save_approval_request(self, req: ApprovalRequest) -> None:
        with self._lock:
            self._approvals[req.approval_id] = req.model_copy(deep=True)

    def get_approval_request(self, approval_id: str) -> ApprovalRequest:
        with self._lock:
            return self._get(self._approvals, approval_id)

    def update_approval_request(
        self, req: ApprovalRequest, expected_status: str, expected_step: int
    ) -> None:
        with self._lock:
            cur = self._approvals.get(req.approval_id)
            if cur is None:
                raise NotFound(req.approval_id)
            if cur.status != expected_status or cur.current_step != expected_step:
                raise StaleState(f"{req.approval_id}: {cur.status}/{cur.current_step}")
            self._approvals[req.approval_id] = req.model_copy(deep=True)

    def record_decision(
        self,
        decision: ApprovalDecision,
        req: ApprovalRequest,
        expected_status: str,
        expected_step: int,
    ) -> None:
        with self._lock:
            cur = self._approvals.get(req.approval_id)
            if cur is None:
                raise NotFound(req.approval_id)
            key = (decision.approval_id, decision.step)
            stale = cur.status != expected_status or cur.current_step != expected_step
            if stale or any((d.approval_id, d.step) == key for d in self._decisions):
                raise StaleState(f"{req.approval_id}: {cur.status}/{cur.current_step}")
            self._decisions.append(decision.model_copy(deep=True))
            self._approvals[req.approval_id] = req.model_copy(deep=True)

    def list_due_approvals(self, now: datetime) -> list[ApprovalRequest]:
        with self._lock:
            return [
                r.model_copy(deep=True)
                for r in self._approvals.values()
                if r.status == "PENDING" and r.step_expires_at <= now
            ]

    def save_approval_decision(self, decision: ApprovalDecision) -> None:
        with self._lock:
            key = (decision.approval_id, decision.step)
            if any((d.approval_id, d.step) == key for d in self._decisions):
                raise StaleState(f"decision exists: {key}")
            self._decisions.append(decision.model_copy(deep=True))

    def get_approval_decision(self, approval_id: str) -> ApprovalDecision | None:
        with self._lock:
            for d in reversed(self._decisions):
                if d.approval_id == approval_id:
                    return d.model_copy(deep=True)
            return None

    def list_approvals(self, statuses: set[ApprovalStatus]) -> list[ApprovalRequest]:
        with self._lock:
            return [
                r.model_copy(deep=True) for r in self._approvals.values() if r.status in statuses
            ]

    def add_dead_letter(self, dl: DeadLetter) -> None:
        with self._lock:
            self._dead[dl.run_id].append(dl.model_copy(deep=True))

    def list_dead_letters(self, run_id: str) -> list[DeadLetter]:
        with self._lock:
            return [d.model_copy(deep=True) for d in self._dead.get(run_id, [])]

    def add_spend(self, agent_id: str, day: date, usd: Decimal) -> tuple[Decimal, Decimal]:
        with self._lock:
            self._spend[(agent_id, day)] += usd
            month = sum(
                v
                for (a, d), v in self._spend.items()
                if a == agent_id and (d.year, d.month) == (day.year, day.month)
            )
            return self._spend[(agent_id, day)], Decimal(month)

    def spend_totals(self, agent_id: str, day: date) -> tuple[Decimal, Decimal]:
        with self._lock:
            month = sum(
                (
                    v
                    for (a, d), v in self._spend.items()
                    if a == agent_id and (d.year, d.month) == (day.year, day.month)
                ),
                Decimal(0),
            )
            return self._spend.get((agent_id, day), Decimal(0)), month

    def get_kill_switch(self) -> KillSwitch:
        with self._lock:
            return self._kill.model_copy(deep=True)

    def set_kill_switch(self, ks: KillSwitch) -> None:
        with self._lock:
            self._kill = ks.model_copy(deep=True)

    def get_tick_state(self, step: str) -> TickState | None:
        with self._lock:
            state = self._ticks.get(step)
            return state.model_copy() if state else None

    def save_tick_state(self, state: TickState) -> None:
        with self._lock:
            self._ticks[state.step] = state.model_copy()
