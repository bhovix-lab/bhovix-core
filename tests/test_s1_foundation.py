"""S1: config, models, store, run state machine."""

from datetime import timedelta
from decimal import Decimal

import pytest
import yaml

from bhovix_core.config import ConfigError, load_config
from bhovix_core.models import Plan, Run, RunState, Target, canonical_json, now, sha256_hex
from bhovix_core.runtime.runs import ALLOWED, FINAL, IllegalTransition, advance
from bhovix_core.store import MemoryStore, StaleState
from bhovix_core.store.protocol import NotFound

S = RunState


def _edit(cfg_dir, fn, name="config.yaml"):
    path = cfg_dir / name
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    fn(data)
    path.write_text(yaml.safe_dump(data), encoding="utf-8")


# --- config -------------------------------------------------------------------


def test_fixture_config_loads(cfg_dir):
    cfg = load_config(cfg_dir)
    assert cfg.routes["default"].input_usd_per_mtok == Decimal("3.00")
    assert "127.0.0.1" in cfg.egress_hosts
    assert cfg.audit_dir == cfg_dir / "audit"


def test_config_dir_from_env(cfg_dir, monkeypatch):
    monkeypatch.setenv("BHOVIX_CONFIG_DIR", str(cfg_dir))
    assert load_config().root == cfg_dir


def test_bad_unknown_backend(cfg_dir):
    _edit(cfg_dir, lambda d: d["backends"].update(llm="openai"))
    with pytest.raises(ConfigError):
        load_config(cfg_dir)


def test_bad_region_missing_for_aws_backend(cfg_dir):
    _edit(cfg_dir, lambda d: d["backends"].update(llm="bedrock"))
    with pytest.raises(ConfigError, match="region"):
        load_config(cfg_dir)


@pytest.mark.parametrize("value", [-0.1, 1.5])
def test_bad_threshold(cfg_dir, value):
    _edit(cfg_dir, lambda d: d.update(detector_threshold=value))
    with pytest.raises(ConfigError):
        load_config(cfg_dir)


def test_bad_empty_egress_with_real_backend(cfg_dir):
    def real(d):
        d["backends"].update(llm="bedrock")
        d["region"] = "test-region-1"

    _edit(cfg_dir, real)
    _edit(cfg_dir, lambda d: d.update(hosts=[]), name="egress.yaml")
    with pytest.raises(ConfigError, match="egress"):
        load_config(cfg_dir)


def test_bad_float_money(cfg_dir):
    _edit(cfg_dir, lambda d: d["routes"]["default"].update(input_usd_per_mtok=3.0))
    with pytest.raises(ConfigError, match="decimal"):
        load_config(cfg_dir)


# --- models and hashing -------------------------------------------------------


def _plan(**kw):
    base = {
        "run_id": "run-1",
        "agent_id": "test-agent",
        "action_id": "create_draft_record",
        "action_version": 1,
        "risk_class": "reversible",
        "inputs": {"title": "Desk", "amount": "12.50"},
        "target": Target(system="fixture-records"),
        "idempotency_key": "run-1:create_draft_record",
        "expected_outcome": "one draft record",
    }
    base.update(kw)
    return Plan(**base)


def test_hash_ignores_key_order():
    assert sha256_hex({"a": 1, "b": "x"}) == sha256_hex({"b": "x", "a": 1})


def test_hash_refuses_floats():
    with pytest.raises(ValueError, match="float"):
        canonical_json({"amount": 12.5})


def test_plan_hash_changes_with_inputs():
    p = _plan()
    assert p.hash() == p.model_copy().hash()
    assert p.hash() != p.model_copy(update={"inputs": {"title": "Desk", "amount": "99"}}).hash()


def test_schema_version_round_trip():
    p = _plan()
    back = Plan.model_validate_json(p.model_dump_json())
    assert back == p and back.schema_version == 1


# --- run state machine + store ------------------------------------------------


def _run(store):
    run = Run(
        agent_id="test-agent", principal_id="svc:test-agent", trigger_kind="event", trigger_ref="t"
    )
    store.create_run(run)
    return run


@pytest.mark.parametrize("frm,to", [(f, t) for f, ts in ALLOWED.items() for t in ts])
def test_every_legal_transition(frm, to):
    store = MemoryStore()
    run = _run(store)
    store._runs[run.run_id] = run.model_copy(update={"state": frm})
    assert advance(store, run.run_id, frm, to).state == to


def test_any_non_final_can_stop():
    for frm in ALLOWED:
        store = MemoryStore()
        run = _run(store)
        store._runs[run.run_id] = run.model_copy(update={"state": frm})
        assert advance(store, run.run_id, frm, S.STOPPED).state == S.STOPPED


@pytest.mark.parametrize("frm,to", [(S.RECEIVED, S.EXECUTING), (S.WORKING, S.SUCCEEDED)])
def test_illegal_transition_raises(frm, to):
    store = MemoryStore()
    run = _run(store)
    with pytest.raises(IllegalTransition):
        advance(store, run.run_id, frm, to)


def test_final_states_have_no_exit():
    assert S.SUCCEEDED in FINAL and S.STOPPED in FINAL
    with pytest.raises(IllegalTransition):
        advance(MemoryStore(), "x", S.SUCCEEDED, S.STOPPED)


def test_compare_and_set_refuses_stale_state():
    store = MemoryStore()
    run = _run(store)
    advance(store, run.run_id, S.RECEIVED, S.WORKING)
    with pytest.raises(StaleState):
        advance(store, run.run_id, S.RECEIVED, S.WORKING)


def test_store_returns_copies_and_not_found():
    store = MemoryStore()
    run = _run(store)
    got = store.get_run(run.run_id)
    got.state = S.SUCCEEDED
    assert store.get_run(run.run_id).state == S.RECEIVED
    with pytest.raises(NotFound):
        store.get_run("run-missing")


def test_spend_day_and_month_totals():
    store = MemoryStore()
    today = now().date()
    store.add_spend("a", today, Decimal("0.40"))
    day, month = store.add_spend("a", today, Decimal("0.10"))
    assert day == Decimal("0.50")
    _, month2 = store.add_spend("a", today - timedelta(days=40), Decimal(5))
    assert month == Decimal("0.50") and month2 == Decimal(5)
