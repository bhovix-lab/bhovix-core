"""Run state machine. Runtime is the only writer of run state."""

from __future__ import annotations

from bhovix_core.models import Run, RunState
from bhovix_core.store.protocol import Store

S = RunState

ALLOWED: dict[RunState, frozenset[RunState]] = {
    S.RECEIVED: frozenset({S.WORKING}),
    S.WORKING: frozenset({S.NO_ACTION, S.PLAN_READY, S.NEEDS_PERSON}),
    S.PLAN_READY: frozenset({S.DENIED, S.WAITING_FOR_APPROVAL, S.EXECUTING, S.NEEDS_PERSON}),
    S.WAITING_FOR_APPROVAL: frozenset({S.EXECUTING, S.REJECTED, S.EXPIRED}),
    S.EXECUTING: frozenset({S.VERIFYING, S.NEEDS_PERSON}),
    S.VERIFYING: frozenset({S.SUCCEEDED, S.ROLLED_BACK, S.NEEDS_PERSON}),
}
FINAL = frozenset(s for s in RunState if s not in ALLOWED)


class IllegalTransition(ValueError):
    pass


def check(frm: RunState, to: RunState) -> None:
    if frm in FINAL:
        raise IllegalTransition(f"{frm} is final")
    if to is S.STOPPED or to in ALLOWED[frm]:
        return
    raise IllegalTransition(f"{frm} -> {to}")


def advance(
    store: Store, run_id: str, expected: RunState, new: RunState, reason_code: str | None = None
) -> Run:
    """Legal-transition check, then compare-and-set in the store."""
    check(expected, new)
    return store.transition(run_id, expected, new, reason_code)
