"""Slice 2 P1a: slice 1 fixes and Store additions (design v3 §12.10)."""

from datetime import timedelta
from decimal import Decimal

import pytest
import yaml

from hadavin_sdk.config import load_config
from hadavin_sdk.llm.protocol import ProviderExhausted
from hadavin_sdk.models import ApprovalDecision, Run, RunState, Verdict, now
from hadavin_sdk.registry import load_registry
from hadavin_sdk.store import MemoryStore
from hadavin_sdk.store.protocol import NotFound
from tests.test_s5_runtime import build

S = RunState


def _run(store):
    run = Run(agent_id="a", principal_id="p", trigger_kind="event", trigger_ref="t")
    store.create_run(run)
    return run


def test_provider_exhausted_needs_a_person(cfg_dir):
    rt, cfg = build(cfg_dir)

    def throttled(*a, **k):
        raise ProviderExhausted("throttled after retries")

    rt.llm.chat = throttled
    run = rt.handle("test-agent", "svc:test-agent", (cfg.inputs_dir / "create.txt").read_bytes())
    assert (run.state, run.reason_code) == (S.NEEDS_PERSON, "provider_exhausted")
    assert any(e.error_code == "provider_exhausted" for e in rt.audit.events(run.run_id))


def test_add_cost_unknown_run_is_not_found():
    with pytest.raises(NotFound):
        MemoryStore().add_cost("run-missing", Decimal(1))


def test_touch_moves_updated_at_only():
    store = MemoryStore()
    run = _run(store)
    store._runs[run.run_id] = run.model_copy(update={"updated_at": now() - timedelta(hours=1)})
    store.touch(run.run_id)
    got = store.get_run(run.run_id)
    assert got.updated_at > now() - timedelta(minutes=1) and got.state == S.RECEIVED
    with pytest.raises(NotFound):
        store.touch("run-missing")


def test_list_runs_by_state_and_age():
    store = MemoryStore()
    old, fresh = _run(store), _run(store)
    store._runs[old.run_id] = old.model_copy(
        update={"state": S.EXECUTING, "updated_at": now() - timedelta(hours=1)}
    )
    store._runs[fresh.run_id] = fresh.model_copy(update={"state": S.EXECUTING})
    stuck = store.list_runs(S.EXECUTING, now() - timedelta(minutes=5))
    assert [r.run_id for r in stuck] == [old.run_id]


def test_get_approval_decision_returns_latest_or_none():
    store = MemoryStore()
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


def test_spend_totals_is_a_read_without_a_write():
    store = MemoryStore()
    today = now().date()
    assert store.spend_totals("a", today) == (Decimal(0), Decimal(0))
    assert store._spend == {}  # no row was created by reading
    store.add_spend("a", today, Decimal("0.40"))
    assert store.spend_totals("a", today) == (Decimal("0.40"), Decimal("0.40"))


def test_limits_blocked_does_not_write_spend(cfg_dir):
    rt, _ = build(cfg_dir)
    rt.limits.blocked("test-agent")
    assert rt.store._spend == {}


@pytest.mark.parametrize("score", [-0.1, 1.1])
def test_verdict_score_is_bounded(score):
    with pytest.raises(ValueError):
        Verdict(flagged=True, score=score, backend="x")


def test_config_hash_ignores_new_defaulted_fields_and_sees_backend_swaps(cfg_dir):
    reg = load_registry(load_config(cfg_dir))
    base = reg.config_hash("test-agent")
    # an explicit value equal to the default does not change the hash (exclude_defaults)
    path = cfg_dir / "agents.yaml"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    data[0]["tools_allowed"] = []  # the default
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    assert load_registry(load_config(cfg_dir)).config_hash("test-agent") == base
    # a different llm backend changes it
    swapped = reg.config.model_copy(
        update={"backends": reg.config.backends.model_copy(update={"llm": "bedrock"})}
    )
    assert load_registry(swapped).config_hash("test-agent") != base
