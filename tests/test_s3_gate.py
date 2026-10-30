"""S3: registry cross-file checks, effective risk class and every gate row."""

import pytest
import yaml

from hadavin_sdk.actions.authorizer import authorize
from hadavin_sdk.config import ConfigError, load_config
from hadavin_sdk.models import Plan, Target
from hadavin_sdk.registry import load_registry


def _reg(cfg_dir):
    return load_registry(load_config(cfg_dir))


def _edit(path, fn):
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    data = fn(data) or data
    path.write_text(yaml.safe_dump(data), encoding="utf-8")


def _plan(action="create_draft_record", inputs=None):
    return Plan(
        run_id="run-1",
        agent_id="test-agent",
        action_id=action,
        action_version=1,
        risk_class="reversible",
        inputs={"title": "Desk", "amount": "12.50"} if inputs is None else inputs,
        target=Target(system="fixture-records"),
        idempotency_key=f"run-1:{action}",
        expected_outcome="x",
    )


def _gate(reg, plan, blocked=(), agent=None, principal="svc:test-agent"):
    agent = agent or reg.agents["test-agent"]
    return authorize(
        reg.principals[principal], agent, reg.contracts[plan.action_id], plan, list(blocked)
    )


def test_fixture_registry_loads(cfg_dir):
    reg = _reg(cfg_dir)
    assert set(reg.contracts) == {
        "create_draft_record",
        "lookup_record",
        "delete_record",
        "send_email",
    }
    assert len(reg.config_hash("test-agent")) == 64
    assert len(reg.prompt_sha256("test-agent")) == 64


# --- cross-file "bad config" --------------------------------------------------


def test_bad_unknown_model_route(cfg_dir):
    _edit(cfg_dir / "agents.yaml", lambda d: d[0].update(model_route="nope"))
    with pytest.raises(ConfigError, match="model_route"):
        _reg(cfg_dir)


def test_bad_scope_action_without_contract(cfg_dir):
    _edit(cfg_dir / "agents.yaml", lambda d: d[0]["scope_allowed"].append("pay_invoice"))
    with pytest.raises(ConfigError, match="no contract"):
        _reg(cfg_dir)


def test_bad_unknown_chain(cfg_dir):
    _edit(cfg_dir / "actions" / "lookup_record.yaml", lambda d: d.update(chain_id="nope"))
    with pytest.raises(ConfigError, match="unknown chain"):
        _reg(cfg_dir)


@pytest.mark.parametrize(
    "step", [{"approver_ids": [], "timeout_s": 10}, {"approver_ids": ["user:a"], "timeout_s": 0}]
)
def test_bad_chain_step(cfg_dir, step):
    _edit(cfg_dir / "chains.yaml", lambda d: d[0].update(steps=[step]))
    with pytest.raises(ConfigError, match="step 0"):
        _reg(cfg_dir)


def test_bad_check_function_outside_check_modules(cfg_dir):
    _edit(
        cfg_dir / "actions" / "lookup_record.yaml",
        lambda d: d.update(verify_check="os:system"),
    )
    with pytest.raises(ConfigError, match="check_modules"):
        _reg(cfg_dir)


def test_empty_tools_allowed_means_no_tools(cfg_dir):
    assert _reg(cfg_dir).tools_for("test-agent", {"web_search", "calculator"}) == []


# --- gate rows 1-8 --------------------------------------------------------------


def test_row1_agent_not_live(cfg_dir):
    reg = _reg(cfg_dir)
    agent = reg.agents["test-agent"].model_copy(update={"status": "draft"})
    assert _gate(reg, _plan(), agent=agent).rule_id == "agent.not_live"


def test_row2_send_email_out_of_agent_scope(cfg_dir):
    reg = _reg(cfg_dir)
    d = _gate(reg, _plan("send_email", {"to": "x@example.test", "body": "hi"}))
    assert (d.outcome, d.rule_id) == ("deny", "scope.agent")


def test_row3_principal_lacks_right(cfg_dir):
    reg = _reg(cfg_dir)
    assert _gate(reg, _plan(), principal="user:a").rule_id == "scope.principal"


@pytest.mark.parametrize(
    "inputs",
    [
        {"title": "Desk"},
        {"title": "Desk", "amount": "12.5.0"},
        {"title": "x", "amount": "1", "z": 1},
    ],
)
def test_row4_input_schema(cfg_dir, inputs):
    assert _gate(_reg(cfg_dir), _plan(inputs=inputs)).rule_id == "input.schema"


def test_row5_blocked_by_limits(cfg_dir):
    d = _gate(_reg(cfg_dir), _plan(), blocked=["daily_budget", "kill_switch"])
    assert (d.outcome, d.rule_id) == ("deny", "limits.daily_budget")


def test_row6_sign_off_denied_until_stepup(cfg_dir):
    d = _gate(_reg(cfg_dir), _plan("delete_record", {"id": "rec-001"}))
    assert (d.outcome, d.rule_id) == ("deny", "class.sign_off.no_stepup")


def test_row7_reversible_needs_approval(cfg_dir):
    plan = _plan()
    d = _gate(_reg(cfg_dir), plan)
    assert (d.outcome, d.rule_id) == ("needs_approval", "class.reversible")
    assert d.plan_hash == plan.hash()


def test_row8_read_only_allowed(cfg_dir):
    d = _gate(_reg(cfg_dir), _plan("lookup_record", {"id": "rec-001"}))
    assert (d.outcome, d.rule_id) == ("allow", "class.read_only")


# --- raise rules ------------------------------------------------------------------


@pytest.mark.parametrize("flag", ["targets_production", "changes_spend"])
def test_raise_flag_makes_create_sign_off(cfg_dir, flag):
    _edit(cfg_dir / "actions" / "create_draft_record.yaml", lambda d: d.update({flag: True}))
    assert _gate(_reg(cfg_dir), _plan()).rule_id == "class.sign_off.no_stepup"


@pytest.mark.parametrize("data_class", ["confidential", "restricted"])
def test_raise_data_class_makes_create_sign_off(cfg_dir, data_class):
    reg = _reg(cfg_dir)
    agent = reg.agents["test-agent"].model_copy(update={"data_class": data_class})
    assert _gate(reg, _plan(), agent=agent).rule_id == "class.sign_off.no_stepup"


def test_raise_read_only_to_reversible(cfg_dir):
    _edit(
        cfg_dir / "actions" / "lookup_record.yaml",
        lambda d: d.update(targets_production=True, rollback="tests.fixtures.checks:noop"),
    )
    d = _gate(_reg(cfg_dir), _plan("lookup_record", {"id": "rec-001"}))
    assert (d.outcome, d.rule_id) == ("needs_approval", "class.reversible")


def test_reversible_without_rollback_is_denied(cfg_dir):
    _edit(
        cfg_dir / "actions" / "create_draft_record.yaml",
        lambda d: d.update(rollback=None, rollback_test=None),
    )
    assert _gate(_reg(cfg_dir), _plan()).rule_id == "class.sign_off.no_stepup"
