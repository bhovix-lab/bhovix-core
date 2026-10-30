"""Limits: spend meter, daily and monthly budgets, kill switch. Every stop and reset is audited."""

from __future__ import annotations

from decimal import Decimal

from bhovix_core.audit.protocol import AuditSink
from bhovix_core.models import AuditEvent, KillSwitch, now
from bhovix_core.registry import Registry
from bhovix_core.store.protocol import Store


class Limits:
    def __init__(self, store: Store, audit: AuditSink, registry: Registry) -> None:
        self.store, self.audit, self.registry = store, audit, registry

    def charge(self, agent_id: str, usd: Decimal) -> tuple[Decimal, Decimal]:
        return self.store.add_spend(agent_id, now().date(), usd)

    def blocked(self, agent_id: str) -> list[str]:
        reasons = []
        if self.store.get_kill_switch().on:
            reasons.append("kill_switch")
        day, month = self.store.add_spend(agent_id, now().date(), Decimal(0))
        budget = self.registry.agents[agent_id].budget_usd
        if day >= budget.daily:
            reasons.append("daily_budget")
        if month >= budget.monthly:
            reasons.append("monthly_budget")
        return reasons

    def _set(self, on: bool, by: str, operation: str) -> None:
        self.audit.write_intent(
            AuditEvent(
                run_id="-",
                domain="limits",
                operation=operation,
                principal=by,
                source="cli",
                result="on" if on else "off",
            )
        )
        self.store.set_kill_switch(KillSwitch(on=on, by=by))

    def stop(self, by: str) -> None:
        self._set(True, by, "stop")

    def reset(self, by: str) -> None:
        self._set(False, by, "reset")
