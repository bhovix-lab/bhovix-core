"""S5: agent loop, plan builder, limits, start-up qualification."""

from decimal import Decimal

import pytest
import yaml

from hadavin_sdk.audit import LocalDirSink
from hadavin_sdk.config import load_config
from hadavin_sdk.guard import RegexDetector
from hadavin_sdk.limits import Limits
from hadavin_sdk.llm import FakeLLM
from hadavin_sdk.models import RunState, now
from hadavin_sdk.registry import load_registry
from hadavin_sdk.runtime.agent_loop import Hooks, Runtime, Unqualified
from hadavin_sdk.store import MemoryStore
from tests.conftest import qualify

S = RunState


def build(cfg_dir, hooks=None, qualified=True):
    cfg = load_config(cfg_dir)
    reg = load_registry(cfg)
    if qualified:
        qualify(reg)
    store, audit = MemoryStore(), LocalDirSink(cfg.audit_dir)
    limits = Limits(store, audit, reg)
    rt = Runtime(
        reg,
        store,
        audit,
        FakeLLM(cfg.recorded_dir, cfg.routes),
        RegexDetector(cfg.detector_threshold),
        limits,
        ["test-agent"],
        hooks,
    )
    return rt, cfg


def _doc(cfg, name):
    return (cfg.inputs_dir / name).read_bytes()


def test_startup_refuses_unqualified_agent(cfg_dir):
    with pytest.raises(Unqualified):
        build(cfg_dir, qualified=False)


def test_startup_refuses_stale_qualification(cfg_dir):
    cfg = load_config(cfg_dir)
    qualify(load_registry(cfg))
    prompt = cfg_dir / "prompts" / "test-agent.md"
    prompt.write_text(prompt.read_text(encoding="utf-8") + "Changed.\n", encoding="utf-8")
    with pytest.raises(Unqualified):
        build(cfg_dir, qualified=False)


def test_injected_document_needs_a_person(cfg_dir):
    rt, cfg = build(cfg_dir)
    run = rt.handle("test-agent", "svc:test-agent", _doc(cfg, "injected.txt"))
    assert (run.state, run.reason_code) == (S.NEEDS_PERSON, "injection_suspected")
    assert rt.llm.calls == []  # the model never saw it


def test_plan_built_and_reversible_waits_for_approval_hook(cfg_dir):
    seen = []
    rt, cfg = build(cfg_dir, Hooks(request_approval=lambda p, d, r: seen.append((p, d))))
    run = rt.handle("test-agent", "svc:test-agent", _doc(cfg, "create.txt"))
    assert run.state == S.WAITING_FOR_APPROVAL
    plan, decision = seen[0]
    assert plan.inputs == {"title": "Standing desk", "amount": "249.00"}
    assert plan.idempotency_key == f"{run.run_id}:create_draft_record"
    assert decision.plan_hash == plan.hash() and decision.rule_id == "class.reversible"
    assert rt.store.get_run(run.run_id).cost_usd == Decimal("0.00225")


def test_sign_off_denied(cfg_dir):
    rt, cfg = build(cfg_dir)
    run = rt.handle("test-agent", "svc:test-agent", _doc(cfg, "delete.txt"))
    assert (run.state, run.reason_code) == (S.DENIED, "class.sign_off.no_stepup")


def test_text_reply_is_no_action(cfg_dir):
    rt, cfg = build(cfg_dir)
    assert rt.handle("test-agent", "svc:test-agent", _doc(cfg, "chat.txt")).state == S.NO_ACTION


def test_max_steps_stops_the_loop(cfg_dir):
    path = cfg_dir / "agents.yaml"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    data[0]["tools_allowed"] = ["echo"]
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    rt, cfg = build(cfg_dir, Hooks(tools={"echo": lambda inp: inp["text"]}))
    run = rt.handle("test-agent", "svc:test-agent", _doc(cfg, "loop.txt"))
    assert (run.state, run.reason_code) == (S.NEEDS_PERSON, "max_steps")
    assert len(rt.llm.calls) == 4


def test_tool_not_in_tools_allowed_is_unknown(cfg_dir):
    rt, cfg = build(cfg_dir, Hooks(tools={"echo": lambda inp: "x"}))
    run = rt.handle("test-agent", "svc:test-agent", _doc(cfg, "loop.txt"))
    assert (run.state, run.reason_code) == (S.NEEDS_PERSON, "unknown_action")


def test_budget_crossed_by_this_call_is_denied_at_the_gate(cfg_dir):
    rt, cfg = build(cfg_dir)
    rt.limits.charge("test-agent", Decimal("0.999"))  # the call costs 0.00225 and crosses 1.00
    run = rt.handle("test-agent", "svc:test-agent", _doc(cfg, "create.txt"))
    assert (run.state, run.reason_code) == (S.DENIED, "limits.daily_budget")


def test_budget_already_spent_stops_before_the_model(cfg_dir):
    rt, cfg = build(cfg_dir)
    rt.limits.charge("test-agent", Decimal("1.00"))
    run = rt.handle("test-agent", "svc:test-agent", _doc(cfg, "create.txt"))
    assert (run.state, run.reason_code) == (S.NEEDS_PERSON, "limits.daily_budget")
    assert rt.llm.calls == []


def test_kill_switch_stops_and_reset_is_audited(cfg_dir):
    rt, cfg = build(cfg_dir)
    rt.limits.stop(by="user:a")
    run = rt.handle("test-agent", "svc:test-agent", _doc(cfg, "create.txt"))
    assert (run.state, run.reason_code) == (S.STOPPED, "kill_switch")
    rt.limits.reset(by="user:a")
    assert rt.limits.blocked("test-agent") == []
    ops = [(e.domain, e.operation, e.principal) for e in rt.audit.events("-")]
    assert ops == [("limits", "stop", "user:a"), ("limits", "reset", "user:a")]


def test_every_step_audited_under_the_run_id(cfg_dir):
    rt, cfg = build(cfg_dir)
    run = rt.handle("test-agent", "svc:test-agent", _doc(cfg, "delete.txt"))
    events = rt.audit.events(run.run_id)
    assert [e.operation for e in events][:2] == ["received", "state"]
    gate = [e for e in events if e.domain == "gate"]
    assert gate[0].decision == "deny" and gate[0].rule_id == "class.sign_off.no_stepup"
    assert all(e.ts <= now() for e in events)
