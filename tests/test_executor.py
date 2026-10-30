"""S7: executor against fixture-records; verify, rollback, timeout lookup, hash re-check."""

import pytest

from hadavin_sdk.actions.executor import Executor
from hadavin_sdk.actions.secrets import FakeSecretProvider
from hadavin_sdk.config import load_config
from hadavin_sdk.models import ApprovalDecision, GateDecision, Plan, RunResult, Target
from hadavin_sdk.registry import load_registry


@pytest.fixture
def ex(live_cfg_dir, fake_system):
    reg = load_registry(load_config(live_cfg_dir))
    return Executor(reg, FakeSecretProvider({"fixture-token": fake_system.token}), timeout_s=0.5)


def _plan(action="create_draft_record", inputs=None):
    return Plan(
        run_id="run-1",
        agent_id="test-agent",
        action_id=action,
        action_version=1,
        risk_class="reversible",
        inputs=inputs or {"title": "Desk", "amount": "12.50"},
        target=Target(system="fixture-records", ref=(inputs or {}).get("id")),
        idempotency_key=f"run-1:{action}",
        expected_outcome="x",
    )


def _approved(plan):
    gd = GateDecision(run_id="run-1", plan_hash=plan.hash(), outcome="needs_approval", rule_id="r")
    ad = ApprovalDecision(
        approval_id="apr-1",
        plan_hash=plan.hash(),
        step=0,
        decision="approve",
        approver_id="user:a",
        channel="fake",
    )
    return gd, ad


def test_create_verify_ok(ex, fake_system):
    plan = _plan()
    result = ex.execute(plan, *_approved(plan))
    assert result.outcome == "succeeded" and result.external_ref == "rec-001"
    assert ex.verify(plan, result)
    assert fake_system.creates == 1


def test_timeout_then_lookup_exactly_one_record(ex, fake_system):
    fake_system.timeout_once_on_create = True
    plan = _plan()
    result = ex.execute(plan, *_approved(plan))
    assert result.outcome == "succeeded" and result.external_ref == "rec-001"
    assert fake_system.creates == 1 and len(fake_system.records) == 1


def test_timeout_and_lookup_fails_is_unknown(ex, fake_system):
    fake_system.timeout_once_on_create = True
    fake_system.fail_lookups = True
    plan = _plan()
    result = ex.execute(plan, *_approved(plan))
    assert (result.outcome, result.error_code) == ("unknown", "lookup_failed")
    assert fake_system.creates == 1  # never retried blindly


def test_changed_stored_plan_refused(ex, fake_system):
    plan = _plan()
    gd, ad = _approved(plan)
    tampered = plan.model_copy(update={"inputs": {"title": "Desk", "amount": "9999.00"}})
    assert ex.execute(tampered, gd, ad).error_code == "plan_hash_mismatch"
    assert fake_system.creates == 0


def test_needs_approval_without_approval_refused(ex, fake_system):
    plan = _plan()
    gd, _ = _approved(plan)
    assert ex.execute(plan, gd, None).error_code == "not_approved"
    assert fake_system.creates == 0


def test_verify_mismatch_detected(ex, fake_system):
    plan = _plan()
    result = ex.execute(plan, *_approved(plan))
    fake_system.verify_mismatch = True
    assert not ex.verify(plan, result)


def test_rollback_delete_draft_record(ex, fake_system):
    """The named rollback test for create_draft_record (repo rule: reversible contracts name it)."""
    plan = _plan()
    result = ex.execute(plan, *_approved(plan))
    assert fake_system.records
    rb = ex.rollback(plan, result)
    assert rb == RunResult(outcome="succeeded", external_ref="rec-001")
    assert fake_system.records == {}


def test_read_only_lookup(ex, fake_system):
    create = _plan()
    assert ex.execute(create, *_approved(create)).outcome == "succeeded"
    plan = _plan("lookup_record", {"id": "rec-001"})
    gd = GateDecision(run_id="run-1", plan_hash=plan.hash(), outcome="allow", rule_id="r")
    result = ex.execute(plan, gd)
    assert result.outcome == "succeeded"
    assert ex.verify(plan, result)


def test_wrong_token_is_refused_by_the_system(live_cfg_dir, fake_system):
    reg = load_registry(load_config(live_cfg_dir))
    bad = Executor(reg, FakeSecretProvider({"fixture-token": "not-" + "the-token"}), timeout_s=0.5)
    plan = _plan()
    assert bad.execute(plan, *_approved(plan)).error_code == "http_401"


def test_unknown_host_refused_before_any_call(live_cfg_dir, fake_system):
    cfg = load_config(live_cfg_dir)
    reg = load_registry(cfg.model_copy(update={"egress_hosts": frozenset({"other.example"})}))
    refused = Executor(reg, FakeSecretProvider({"fixture-token": fake_system.token}))
    plan = _plan()
    assert refused.execute(plan, *_approved(plan)).error_code == "egress_refused"
    assert fake_system.creates == 0
