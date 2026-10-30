"""`hadavin-sdk tick`: one idempotent pass of housekeeping steps, run every 30-60 s by any scheduler.

Contract (design v5 kernel, section 4):
* ``STEPS`` runs in order: sweep, reconcile, stuck, checkpoint. Later PRs only **append** a ``TickStep``.
* Each step runs in its own ``try``: a failure is logged as ``step=<name> error_kind=<type>
  message=<redacted, <= 500 chars>`` and written to ``tick_state``; the other steps still run.
* A step with ``every_s > 0`` runs only if ``now - tick_state.last_run_at >= every_s``.
* ``heartbeat`` always runs last and reports this tick's outcome.
* Exit codes: 0 all ok; 1 a step failed; 2 config error; 3 store unreachable (both before any step).

Concurrent ticks are safe: every state change is a compare-and-set, and a loser (``StaleState``) skips.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any

from hadavin_sdk.guard.redact import redact
from hadavin_sdk.models import AuditEvent, RunState, TickState
from hadavin_sdk.runtime.runs import IllegalTransition, advance
from hadavin_sdk.store.protocol import StaleState

if TYPE_CHECKING:
    from hadavin_sdk.app import App

S = RunState
_LOG = logging.getLogger("hadavin_sdk.tick")
OK, FAILED, SKIPPED = "ok", "failed", "skipped"


@dataclass
class TickContext:
    app: App
    now: datetime
    results: dict[str, str] = field(default_factory=dict)  # step name -> ok / failed / skipped


@dataclass(frozen=True)
class TickStep:
    name: str  # unique, [a-z_]+
    every_s: int  # 0 = every tick
    fn: Callable[[TickContext], None]


def _each(items: list[Any], fn: Callable[[Any], None], what: str) -> None:
    """Run fn per item; a CAS loser is skipped quietly, any other error is logged and the step fails at the
    end, after every item had its turn (one bad row never blocks the rest)."""
    first: Exception | None = None
    for item in items:
        try:
            fn(item)
        except (StaleState, IllegalTransition):
            _LOG.debug("%s: moved by another worker, skipped", what)
        except Exception as exc:  # noqa: BLE001 - isolate the item; re-raised below
            _LOG.warning("%s: %s", what, type(exc).__name__)
            first = first or exc
    if first is not None:
        raise first


def sweep(ctx: TickContext) -> None:
    """Escalate or expire due approvals; resend requests whose channel send failed."""
    ctx.app.approvals.sweep(ctx.now)
    ctx.app.approvals.resend_unsent()


def reconcile(ctx: TickContext) -> None:
    """Advance runs whose approval ended (APPROVED runs the plan). The receiver only records decisions."""
    store, runtime = ctx.app.store, ctx.app.runtime
    ended = store.list_approvals({"APPROVED", "REJECTED", "EXPIRED"})
    # ponytail: scans every ended approval each tick; filter by a reconciled flag when the table grows.

    def one(req) -> None:
        if store.get_run(req.run_id).state is not S.WAITING_FOR_APPROVAL:
            return
        runtime.on_decided(req.run_id, req.status, store.get_approval_decision(req.approval_id))

    _each(ended, one, "reconcile")


def stuck_after_s(app: App, agent_id: str) -> float:
    """max_steps x call_timeout_s x max_attempts + 60 (design 12.7): the longest a healthy run stays quiet."""
    llm = app.config.backends.llm
    agent = app.registry.agents.get(agent_id)
    steps = (
        agent.max_steps
        if agent
        else max((a.max_steps for a in app.registry.agents.values()), default=1)
    )
    return steps * getattr(llm, "call_timeout_s", 60) * getattr(llm, "max_attempts", 1) + 60


STUCK = {
    S.RECEIVED: "interrupted",
    S.WORKING: "interrupted",
    S.EXECUTING: "outcome_unknown",  # never re-executed: a person checks the system
    # ponytail: re-run verify once needs the stored RunResult; until then a person checks.
    S.VERIFYING: "verify_interrupted",
}


def stuck(ctx: TickContext) -> None:
    """Runs quiet for longer than their agent's stuck_after_s go to NEEDS_PERSON with a reason."""
    app = ctx.app
    floor = min((stuck_after_s(app, a) for a in app.registry.agents), default=60)
    for state, reason in STUCK.items():
        candidates = app.store.list_runs(state, ctx.now - timedelta(seconds=floor))

        def one(run, state=state, reason=reason) -> None:
            if run.updated_at >= ctx.now - timedelta(seconds=stuck_after_s(app, run.agent_id)):
                return
            advance(app.store, run.run_id, state, S.NEEDS_PERSON, reason)
            app.audit.write_outcome(
                AuditEvent(
                    run_id=run.run_id,
                    domain="run",
                    operation="state",
                    principal="system:tick",
                    source="tick",
                    result=S.NEEDS_PERSON.value,
                    error_code=reason,
                )
            )

        _each(candidates, one, f"stuck {state.value}")


def checkpoint(ctx: TickContext) -> None:
    """Sign an audit checkpoint when the audit kind has them (`chain`); others have nothing to do."""
    fn = getattr(ctx.app.audit, "checkpoint", None)
    if fn is not None:
        fn()


def heartbeat(ctx: TickContext) -> None:
    """Always last: one line with this tick's outcome (K7 adds the metric the dead-man alarm watches)."""
    failed = sorted(n for n, r in ctx.results.items() if r == FAILED)
    _LOG.info("tick ok=%s failed=%s", not failed, ",".join(failed) or "-")


STEPS: list[TickStep] = [
    TickStep("sweep", 0, sweep),
    TickStep("reconcile", 0, reconcile),
    TickStep("stuck", 0, stuck),
    TickStep("checkpoint", 0, checkpoint),
]
HEARTBEAT = TickStep("heartbeat", 0, heartbeat)


def _message(exc: Exception) -> str:
    return redact(str(exc)).text.replace("\n", " ")[:500]


def _run_step(ctx: TickContext, step: TickStep) -> str:
    store = ctx.app.store
    prev = store.get_tick_state(step.name)
    if step.every_s and prev and (ctx.now - prev.last_run_at).total_seconds() < step.every_s:
        return SKIPPED
    error = None
    try:
        step.fn(ctx)
    except Exception as exc:  # noqa: BLE001 - one step never stops the others
        error = f"{type(exc).__name__}: {_message(exc)}"
        _LOG.error("step=%s error_kind=%s message=%s", step.name, type(exc).__name__, _message(exc))
    try:
        store.save_tick_state(
            TickState(
                step=step.name,
                last_run_at=ctx.now,
                last_ok_at=ctx.now if error is None else (prev.last_ok_at if prev else None),
                last_error=error,
            )
        )
    except Exception as exc:  # noqa: BLE001 - an unrecorded step counts as failed
        _LOG.error(
            "step=%s error_kind=%s message=tick_state not saved", step.name, type(exc).__name__
        )
        return FAILED
    return OK if error is None else FAILED


def run_tick(app: App, now: datetime | None = None, steps: list[TickStep] | None = None) -> int:
    """One tick. Returns the exit code (0, 1 or 3; 2 is the caller's, for a config that does not load)."""
    ctx = TickContext(app, now or app.approvals.clock())
    try:
        app.store.get_tick_state(HEARTBEAT.name)  # the store answers, or nothing runs
    except Exception as exc:  # noqa: BLE001 - any store failure: change nothing
        _LOG.error("step=- error_kind=%s message=store unreachable", type(exc).__name__)
        return 3
    for step in [*(STEPS if steps is None else steps), HEARTBEAT]:
        ctx.results[step.name] = _run_step(ctx, step)
    return 1 if FAILED in ctx.results.values() else 0
