"""Slice 2 P1a: slice 1 fixes and Store additions (design v3 §12.10).

The Store tests use only the public Store Protocol and run over the `store` fixture, so P2 adds `postgres` to
STORES and they run unchanged against it.
"""

import logging
import time
from datetime import timedelta
from decimal import Decimal

import pytest
import yaml

from hadavin_sdk.actions.executor import Executor
from hadavin_sdk.actions.secrets import FakeSecretProvider
from hadavin_sdk.config import load_config
from hadavin_sdk.guard.injection import injection_check
from hadavin_sdk.llm.protocol import ProviderExhausted
from hadavin_sdk.models import (
    ApprovalDecision,
    ApprovalRequest,
    ChainStep,
    Run,
    RunState,
    Verdict,
    now,
)
from hadavin_sdk.registry import load_registry
from hadavin_sdk.store import MemoryStore
from hadavin_sdk.store.protocol import NotFound
from tests.test_executor import _approved, _plan
from tests.test_s5_runtime import build

S = RunState
STORES = {"memory": MemoryStore}  # P2 adds "postgres"


@pytest.fixture(params=sorted(STORES))
def store(request):
    return STORES[request.param]()


def _run(store, state=S.RECEIVED):
    run = Run(agent_id="a", principal_id="p", trigger_kind="event", trigger_ref="t")
    store.create_run(run)
    if state is not S.RECEIVED:
        store.transition(run.run_id, S.RECEIVED, state)
    return store.get_run(run.run_id)


def _request(store, status="PENDING"):
    req = ApprovalRequest(
        run_id="run-x",
        plan_hash="h",
        risk_class="reversible",
        chain_id="c",
        steps=[ChainStep(approver_ids=["user:a"], timeout_s=60)],
        status=status,
        step_expires_at=now() + timedelta(minutes=1),
        requested_by="svc:a",
        summary="s",
    )
    store.save_approval_request(req)
    return req


# --- Store additions (public API only) ---------------------------------------------------------------


def test_add_cost_unknown_run_is_not_found(store):
    with pytest.raises(NotFound):
        store.add_cost("run-missing", Decimal(1))


def test_touch_moves_updated_at_and_keeps_state(store):
    run = _run(store, S.WORKING)
    time.sleep(0.01)
    store.touch(run.run_id)
    got = store.get_run(run.run_id)
    assert got.updated_at > run.updated_at and got.state == S.WORKING
    with pytest.raises(NotFound):
        store.touch("run-missing")


def test_list_runs_by_state_age_and_limit(store):
    a, b = _run(store, S.WORKING), _run(store, S.WORKING)
    _run(store, S.RECEIVED)
    cutoff = now() + timedelta(seconds=1)
    found = store.list_runs(S.WORKING, cutoff)
    assert {r.run_id for r in found} == {a.run_id, b.run_id}
    assert [r.run_id for r in found] == sorted(
        [a.run_id, b.run_id], key=lambda i: store.get_run(i).updated_at
    )  # oldest first
    assert len(store.list_runs(S.WORKING, cutoff, limit=1)) == 1
    assert store.list_runs(S.WORKING, a.updated_at - timedelta(seconds=1)) == []


def test_get_approval_decision_returns_latest_or_none(store):
    assert store.get_approval_decision("apr-x") is None
    for decision in ("reject", "approve"):
        store.save_approval_decision(
            ApprovalDecision(
                approval_id="apr-x",
                plan_hash="h",
                step=0,
                decision=decision,
                approver_id="user:a",
                channel="fake",
            )
        )
    assert store.get_approval_decision("apr-x").decision == "approve"


def test_list_approvals_by_status(store):
    pending, done = _request(store), _request(store)
    store.update_approval_request(done.model_copy(update={"status": "APPROVED"}), "PENDING", 0)
    assert [r.approval_id for r in store.list_approvals({"PENDING"})] == [pending.approval_id]
    assert {r.approval_id for r in store.list_approvals({"PENDING", "APPROVED"})} == {
        pending.approval_id,
        done.approval_id,
    }
    assert store.list_approvals({"EXPIRED"}) == []


def test_spend_totals_reads_without_writing(store):
    today = now().date()
    assert store.spend_totals("a", today) == (Decimal(0), Decimal(0))
    store.spend_totals("a", today)
    assert store.spend_totals("a", today) == (Decimal(0), Decimal(0))
    store.add_spend("a", today, Decimal("0.40"))
    assert store.spend_totals("a", today) == (Decimal("0.40"), Decimal("0.40"))


# --- runtime, executor, models, registry ------------------------------------------------------------


def test_provider_exhausted_needs_a_person(cfg_dir):
    rt, cfg = build(cfg_dir)

    def throttled(*a, **k):
        raise ProviderExhausted("throttled after retries")

    rt.llm.chat = throttled
    run = rt.handle("test-agent", "svc:test-agent", (cfg.inputs_dir / "create.txt").read_bytes())
    assert (run.state, run.reason_code) == (S.NEEDS_PERSON, "provider_exhausted")
    assert any(e.error_code == "provider_exhausted" for e in rt.audit.events(run.run_id))


def test_executor_heartbeats_before_every_attempt(live_cfg_dir, fake_system):
    reg = load_registry(load_config(live_cfg_dir))
    ex = Executor(reg, FakeSecretProvider({"fixture-token": fake_system.token}), timeout_s=0.5)
    beats = []
    fake_system.timeout_once_on_create = True  # the call times out, then the lookup runs
    plan = _plan()
    result = ex.execute(plan, *_approved(plan), heartbeat=lambda: beats.append(1))
    assert result.outcome == "succeeded"
    assert len(beats) == 2  # one for the call, one for the lookup


def test_runtime_passes_store_touch_as_the_heartbeat(cfg_dir):
    from hadavin_sdk.models import RunResult
    from hadavin_sdk.runtime.agent_loop import Hooks

    seen = {}

    def execute(plan, decision, approval, heartbeat=None):
        before = rt.store.get_run(plan.run_id).updated_at
        time.sleep(0.01)
        heartbeat()
        seen["moved"] = rt.store.get_run(plan.run_id).updated_at > before
        return RunResult(outcome="succeeded", external_ref="rec-001")

    rt, cfg = build(
        cfg_dir,
        Hooks(request_approval=lambda *a: None, execute=execute, verify=lambda p, r: True),
    )
    run = rt.handle("test-agent", "svc:test-agent", (cfg.inputs_dir / "create.txt").read_bytes())
    assert rt.execute(run.run_id).state == S.SUCCEEDED
    assert seen["moved"]


def test_limits_blocked_does_not_write_spend(cfg_dir):
    rt, _ = build(cfg_dir)
    rt.limits.blocked("test-agent")
    assert rt.store.spend_totals("test-agent", now().date()) == (Decimal(0), Decimal(0))


@pytest.mark.parametrize("score", [-0.1, 1.1])
def test_verdict_score_is_bounded(score):
    with pytest.raises(ValueError):
        Verdict(flagged=True, score=score, backend="x")


def test_detector_failure_is_logged_and_flagged(caplog):
    class OutOfRange:
        def check(self, text, source):
            return Verdict(flagged=False, score=7.0, backend="custom")

    with caplog.at_level(logging.WARNING, logger="hadavin_sdk.guard"):
        verdict = injection_check(OutOfRange(), "hello", "document")
    assert verdict.flagged and verdict.reason_code == "guard_unavailable"
    assert "OutOfRange" in caplog.text and "ValidationError" in caplog.text
    assert "hello" not in caplog.text  # the checked text is never logged


# Pinned value: a change here means every deployed agent must be re-gated (CHANGELOG "Upgrade steps").
PINNED_CONFIG_HASH = "505bdd331dbecd6604e7f1a1ae9b0f60486fd8dc024dd1d1821b5e559d918e11"


def test_config_hash_is_pinned(cfg_dir):
    assert load_registry(load_config(cfg_dir)).config_hash("test-agent") == PINNED_CONFIG_HASH


def test_config_hash_ignores_defaulted_fields_and_sees_backend_swaps(cfg_dir):
    reg = load_registry(load_config(cfg_dir))
    base = reg.config_hash("test-agent")
    path = cfg_dir / "agents.yaml"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    data[0]["tools_allowed"] = []  # explicitly the default
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    assert load_registry(load_config(cfg_dir)).config_hash("test-agent") == base
    swapped = reg.config.model_copy(
        update={"backends": reg.config.backends.model_copy(update={"llm": "bedrock"})}
    )
    assert load_registry(swapped).config_hash("test-agent") != base


def test_three_argument_execute_hook_still_works(cfg_dir):
    """CodeRabbit on #7: hooks written before the heartbeat keyword keep working."""
    from hadavin_sdk.models import RunResult
    from hadavin_sdk.runtime.agent_loop import Hooks

    def old_execute(plan, decision, approval):
        return RunResult(outcome="succeeded", external_ref="rec-001")

    rt, cfg = build(
        cfg_dir,
        Hooks(request_approval=lambda *a: None, execute=old_execute, verify=lambda p, r: True),
    )
    run = rt.handle("test-agent", "svc:test-agent", (cfg.inputs_dir / "create.txt").read_bytes())
    assert rt.execute(run.run_id).state == S.SUCCEEDED
