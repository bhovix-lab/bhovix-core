"""Runtime: the agent loop, the plan, the gate hand-off and every run-state write.

Runtime never holds a secret and never imports the executor: ``execute``, ``verify`` and ``rollback`` are injected
by the app wiring (``hadavin_sdk.app``). Approvals are injected the same way.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from hadavin_sdk.actions.authorizer import authorize
from hadavin_sdk.audit.protocol import AuditSink, AuditUnavailable
from hadavin_sdk.config import ConfigError, confined
from hadavin_sdk.guard.injection import Detector, injection_check
from hadavin_sdk.identity import Principal
from hadavin_sdk.limits import Limits
from hadavin_sdk.llm.protocol import LLM
from hadavin_sdk.models import (
    AuditEvent,
    GateDecision,
    GateRun,
    Plan,
    Run,
    RunResult,
    RunState,
    ToolCall,
    sha256_hex,
)
from hadavin_sdk.registry import Registry
from hadavin_sdk.runtime.plan import build_plan
from hadavin_sdk.runtime.runs import advance
from hadavin_sdk.store.protocol import Store

S = RunState
_ASK = "Process the attached request document."


class Unqualified(RuntimeError):
    """The agent has no green gate run for its current model, prompt and config."""


def qualified_runs(registry: Registry) -> list[GateRun]:
    path = registry.config.root / "qualified.jsonl"
    if not path.exists():
        return []
    runs = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            runs.append(GateRun.model_validate_json(line))
        except ValueError:
            # A torn line (disk full mid-append) qualifies nothing, and never blocks the valid lines.
            continue
    return runs


def _check_golden_refs(registry: Registry, agent_id: str) -> None:
    """Every golden input_ref must stay inside inputs_dir: checked at start-up, not only when the gate runs."""
    path = registry.golden_path(agent_id)
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            try:
                ref = json.loads(line)["input_ref"]
            except (ValueError, KeyError, TypeError) as exc:
                raise ConfigError(f"{path.name}: bad golden line") from exc
            confined(registry.config.inputs_dir, ref)


def assert_qualified(registry: Registry, agent_id: str) -> None:
    _check_golden_refs(registry, agent_id)
    agent = registry.agents[agent_id]
    want = (
        registry.config.routes[agent.model_route].model_id,
        registry.prompt_sha256(agent_id),
        registry.config_hash(agent_id),
        registry.golden_sha256(agent_id),  # a weakened golden set also invalidates the run
    )
    for g in qualified_runs(registry):
        got = (g.model_id, g.prompt_sha256, g.config_hash, g.golden_sha256)
        if g.agent_id == agent_id and g.green and got == want:
            return
    raise Unqualified(agent_id)


@dataclass
class Hooks:
    """Injected by the app wiring so runtime never imports the executor or holds secrets."""

    request_approval: Callable[[Plan, GateDecision, str], Any] | None = None
    execute: Callable[..., RunResult] | None = None
    verify: Callable[[Plan, RunResult], bool] | None = None
    rollback: Callable[[Plan, RunResult], RunResult] | None = None
    tools: dict[str, Callable[[dict], str]] = field(default_factory=dict)


class Runtime:
    def __init__(
        self,
        registry: Registry,
        store: Store,
        audit: AuditSink,
        llm: LLM,
        detector: Detector,
        limits: Limits,
        agents: list[str],
        hooks: Hooks | None = None,
    ) -> None:
        for agent_id in agents:  # start-up refuses an unqualified agent
            assert_qualified(registry, agent_id)
        self.registry, self.store, self.audit = registry, store, audit
        self.llm, self.detector, self.limits = llm, detector, limits
        self.agents = set(agents)
        self.hooks = hooks or Hooks()

    # --- audit helpers ---------------------------------------------------------------------------
    def _event(self, run: Run, domain: str, operation: str, **kw: Any) -> AuditEvent:
        return AuditEvent(
            run_id=run.run_id,
            domain=domain,
            operation=operation,
            principal=run.principal_id,
            source="runtime",
            **kw,
        )

    def _note(self, run: Run, domain: str, operation: str, **kw: Any) -> None:
        self.audit.write_outcome(self._event(run, domain, operation, **kw))

    def _to(self, run: Run, new: RunState, reason: str | None = None) -> Run:
        cur = self.store.get_run(run.run_id)
        run = advance(self.store, run.run_id, cur.state, new, reason)
        self._note(run, "run", "state", result=new.value, error_code=reason)
        return run

    # --- the loop ------------------------------------------------------------------------------
    def handle(
        self,
        agent_id: str,
        principal_id: str,
        document: bytes,
        trigger_kind: str = "event",
        trigger_ref: str = "-",
    ) -> Run:
        if agent_id not in self.agents:
            raise Unqualified(agent_id)
        agent = self.registry.agents[agent_id]
        run = Run(
            agent_id=agent_id,
            principal_id=principal_id,
            trigger_kind=trigger_kind,
            trigger_ref=trigger_ref,
        )
        self.store.create_run(run)
        self._note(run, "run", "received", inputs_hash=sha256_hex(document.hex()))
        run = self._to(run, S.WORKING)

        verdict = injection_check(self.detector, document.decode("utf-8", "replace"), "document")
        if verdict.flagged:
            self._note(run, "guard", "injection", result="flagged", error_code=verdict.reason_code)
            return self._to(run, S.NEEDS_PERSON, verdict.reason_code)

        contracts = {a: self.registry.contracts[a] for a in agent.scope_allowed}
        tools = [
            {"name": c.id, "description": c.description, "input_schema": c.input_schema}
            for c in contracts.values()
        ] + [{"name": t} for t in self.registry.tools_for(agent_id, set(self.hooks.tools))]
        messages: list[dict[str, Any]] = [{"role": "user", "content": _ASK}]
        system = self.registry.prompt(agent_id)

        for _step in range(agent.max_steps):
            blocked = self.limits.blocked(agent_id)
            if "kill_switch" in blocked:
                return self._to(run, S.STOPPED, "kill_switch")
            if blocked:
                return self._to(run, S.NEEDS_PERSON, f"limits.{blocked[0]}")
            reply = self.llm.chat(
                messages,
                system=system,
                route=agent.model_route,
                tools=tools,
                documents=[document],
            )
            self.limits.charge(agent_id, reply.cost_usd)
            self.store.add_cost(run.run_id, reply.cost_usd)
            if not reply.tool_calls:
                return self._to(run, S.NO_ACTION)
            call = reply.tool_calls[0]
            if call.name in self.registry.contracts:
                return self._submit(run, call)
            if call.name in self.hooks.tools and call.name in agent.tools_allowed:
                try:
                    result = str(self.hooks.tools[call.name](call.input))
                except Exception:  # noqa: BLE001 - a broken tool must not strand the run in WORKING
                    self._note(run, "tool", call.name, result="error", error_code="tool_error")
                    return self._to(run, S.NEEDS_PERSON, "tool_error")
                verdict = injection_check(self.detector, result, f"tool:{call.name}")
                if verdict.flagged:  # tool output is untrusted text too
                    self._note(
                        run, "guard", "injection", result="flagged", error_code=verdict.reason_code
                    )
                    return self._to(run, S.NEEDS_PERSON, verdict.reason_code)
                messages += [
                    {"role": "assistant", "content": f"tool {call.name}"},
                    {"role": "user", "content": f"tool result: {result}"},
                ]
                continue
            return self._to(run, S.NEEDS_PERSON, "unknown_action")
        return self._to(run, S.NEEDS_PERSON, "max_steps")

    # --- plan, gate, approvals, execution ----------------------------------------------------------
    def _submit(self, run: Run, call: ToolCall) -> Run:
        agent = self.registry.agents[run.agent_id]
        contract = self.registry.contracts[call.name]
        try:  # model output: a float or a non-string id must not strand the run
            plan = build_plan(run, agent, contract, call)
            plan.hash()
        except ValueError:  # includes pydantic ValidationError and the float refusal
            return self._to(run, S.NEEDS_PERSON, "invalid_proposal")
        self.store.save_plan(plan)
        run = self._to(run, S.PLAN_READY)
        decision = authorize(
            self._principal(run), agent, contract, plan, self.limits.blocked(agent.id)
        )
        try:
            self.audit.write_intent(
                self._event(
                    run,
                    "gate",
                    "decide",
                    object_ref=plan.plan_id,
                    inputs_hash=decision.plan_hash,
                    decision=decision.outcome,
                    rule_id=decision.rule_id,
                )
            )
        except AuditUnavailable:
            return self._to(run, S.NEEDS_PERSON, "audit_unavailable")
        self.store.save_gate_decision(decision)
        if decision.outcome == "deny":
            return self._to(run, S.DENIED, decision.rule_id)
        if decision.outcome == "needs_approval":
            if self.hooks.request_approval is None:
                return self._to(run, S.NEEDS_PERSON, "approvals_not_configured")
            run = self._to(run, S.WAITING_FOR_APPROVAL)
            self.hooks.request_approval(plan, decision, run.principal_id)
            return run
        return self.execute(run.run_id)

    def _principal(self, run: Run) -> Principal:
        """An unknown principal gets no rights, so the gate denies it (scope.principal) and audits it."""
        return self.registry.principals.get(run.principal_id) or Principal(
            id=run.principal_id, kind="service", rights=[]
        )

    def _recheck(self, run: Run, plan: Plan, decision: GateDecision) -> str | None:
        """Re-run the gate at execution time: an approval can wait hours while limits, the kill switch,
        the agent's status or the principal's rights change. Returns a reason to stop, or None."""
        agent = self.registry.agents.get(run.agent_id)
        contract = self.registry.contracts.get(plan.action_id)
        if agent is None or contract is None:
            return "recheck.unknown_agent_or_action"
        if plan.hash() != decision.plan_hash:
            return "plan_changed"
        now_d = authorize(
            self._principal(run), agent, contract, plan, self.limits.blocked(agent.id)
        )
        if now_d.outcome == "deny":
            return f"recheck.{now_d.rule_id}"
        if now_d.outcome != decision.outcome:
            return "recheck.class_changed"
        return None

    def on_decided(self, run_id: str, status: str, approval: Any = None) -> Run:
        """Called by approvals when a request ends: APPROVED runs the plan; anything else is final."""
        run = self.store.get_run(run_id)
        if status == "APPROVED":
            return self.execute(run_id, approval)
        return self._to(run, S.REJECTED if status == "REJECTED" else S.EXPIRED, status.lower())

    def execute(self, run_id: str, approval: Any = None) -> Run:
        run = self.store.get_run(run_id)
        plan = self.store.get_plan(run_id)
        decision = self.store.get_gate_decision(run_id)
        if self.hooks.execute is None:
            return self._to(run, S.NEEDS_PERSON, "executor_not_configured")
        if self.hooks.verify is None:  # an unverified action is never reported as done
            return self._to(run, S.NEEDS_PERSON, "verify_not_configured")
        stop = self._recheck(run, plan, decision)
        if stop is not None:
            self._note(run, "gate", "recheck", object_ref=plan.plan_id, rule_id=stop, result="stop")
            if stop == "recheck.limits.kill_switch":
                return self._to(run, S.STOPPED, "kill_switch")
            return self._to(run, S.NEEDS_PERSON, stop)
        try:
            self.audit.write_intent(
                self._event(
                    run, "action", "execute", object_ref=plan.plan_id, inputs_hash=plan.hash()
                )
            )
        except AuditUnavailable:
            return self._to(run, S.NEEDS_PERSON, "audit_unavailable")
        run = self._to(run, S.EXECUTING)
        try:
            result = self.hooks.execute(plan, decision, approval)
        except Exception:  # noqa: BLE001 - the side effect may have happened: never leave EXECUTING
            result = RunResult(outcome="unknown", error_code="executor_error")
        self._note(
            run,
            "action",
            "result",
            object_ref=result.external_ref,
            result=result.outcome,
            error_code=result.error_code,
        )
        if result.outcome != "succeeded":
            return self._to(run, S.NEEDS_PERSON, result.error_code or f"outcome_{result.outcome}")
        run = self._to(run, S.VERIFYING)
        try:
            verified = bool(self.hooks.verify(plan, result))
        except Exception:  # noqa: BLE001 - an error is "not verified"
            verified = False
            self._note(run, "action", "verify", result="error", error_code="verify_error")
        if verified:
            return self._to(run, S.SUCCEEDED)
        if self.hooks.rollback is not None:
            try:
                rb = self.hooks.rollback(plan, result)
            except Exception:  # noqa: BLE001
                rb = RunResult(outcome="unknown", error_code="rollback_error")
            self._note(run, "action", "rollback", result=rb.outcome, error_code=rb.error_code)
            if rb.outcome == "succeeded":
                return self._to(run, S.ROLLED_BACK, "verify_failed")
        return self._to(run, S.NEEDS_PERSON, "verify_failed")
