"""S8: the critical user journeys end to end on fakes (core-only amendment §7)."""

import json
from datetime import UTC, datetime, timedelta

import pytest

from hadavin_sdk import cli, evals
from hadavin_sdk.actions.secrets import FakeSecretProvider
from hadavin_sdk.app import build, make_llm
from hadavin_sdk.audit import AuditUnavailable
from hadavin_sdk.config import load_config
from hadavin_sdk.guard import EgressRefused, egress_check
from hadavin_sdk.models import ApprovalDecision, RunState, Verdict
from hadavin_sdk.registry import load_registry
from hadavin_sdk.runtime.agent_loop import Unqualified

S = RunState
T0 = datetime(2026, 10, 30, 9, 0, tzinfo=UTC)


class Clock:
    def __init__(self):
        self.t = T0

    def __call__(self):
        return self.t


class NeverFlagDetector:
    """Test-only detector: proves the gate denies even when the tripwire misses."""

    def check(self, text, source):
        return Verdict(flagged=False, score=0.0, backend="never")


def _qualify(cfg_dir):
    cfg = load_config(cfg_dir)
    return evals.gate(load_registry(cfg), make_llm(cfg), "test-agent")


@pytest.fixture
def app(live_cfg_dir, fake_system):
    assert _qualify(live_cfg_dir).green
    clock = Clock()
    a = build(
        live_cfg_dir,
        FakeSecretProvider({"fixture-token": fake_system.token}),
        ["test-agent"],
        clock=clock,
        timeout_s=0.5,
    )
    a.clock = clock
    return a


def _doc(app, name):
    return (app.config.inputs_dir / name).read_bytes()


def _pending(app, run_id):
    return next(r for r in app.store._approvals.values() if r.run_id == run_id)


def _approve(app, req, approver="user:a"):
    return app.approvals.decide(
        ApprovalDecision(
            approval_id=req.approval_id,
            plan_hash=req.plan_hash,
            step=req.current_step,
            decision="approve",
            approver_id=approver,
            channel="fake",
        )
    )


def test_cuj1_reversible_action_approved(app, fake_system):
    run = app.runtime.handle("test-agent", "svc:test-agent", _doc(app, "create.txt"))
    assert run.state == S.WAITING_FOR_APPROVAL
    req = _pending(app, run.run_id)
    assert _approve(app, req) == (True, "approved")
    final = app.store.get_run(run.run_id)
    assert final.state == S.SUCCEEDED
    assert list(fake_system.records.values()) == [
        {"id": "rec-001", "title": "Standing desk", "amount": "249.00"}
    ]
    events = app.audit.events(run.run_id)
    ops = [(e.domain, e.operation) for e in events]
    for needed in [
        ("run", "received"),
        ("gate", "decide"),
        ("approval", "request"),
        ("approval", "decide"),
        ("action", "execute"),
        ("action", "result"),
    ]:
        assert needed in ops
    assert ops.index(("action", "execute")) < ops.index(("action", "result"))
    assert {e.run_id for e in events} == {run.run_id}


def test_cuj2_approver_on_leave_expires_and_nothing_runs(app, fake_system):
    run = app.runtime.handle("test-agent", "svc:test-agent", _doc(app, "create.txt"))
    req = _pending(app, run.run_id)
    for _ in range(3):
        app.clock.t += timedelta(hours=4)
        app.approvals.sweep()
    assert _approve(app, req, "user:a") == (False, "not_pending")
    assert app.store.get_run(run.run_id).state == S.EXPIRED
    assert app.approvals.channel.notices[0][0] == "svc:test-agent"
    assert fake_system.creates == 0


def test_cuj2_old_step_refused(app):
    run = app.runtime.handle("test-agent", "svc:test-agent", _doc(app, "create.txt"))
    req = _pending(app, run.run_id)
    app.clock.t += timedelta(hours=4)
    app.approvals.sweep()
    assert _approve(app, req, "user:a") == (False, "old_step")


def test_cuj3_injected_document(app, fake_system):
    run = app.runtime.handle("test-agent", "svc:test-agent", _doc(app, "injected.txt"))
    assert (run.state, run.reason_code) == (S.NEEDS_PERSON, "injection_suspected")


def test_cuj3_gate_denies_even_when_detector_misses(live_cfg_dir, fake_system):
    assert _qualify(live_cfg_dir).green
    app = build(
        live_cfg_dir,
        FakeSecretProvider({"fixture-token": fake_system.token}),
        ["test-agent"],
        detector=NeverFlagDetector(),
    )
    doc = (app.config.inputs_dir / "injected.txt").read_bytes()
    run = app.runtime.handle("test-agent", "svc:test-agent", doc)
    assert (run.state, run.reason_code) == (S.DENIED, "scope.agent")
    with pytest.raises(EgressRefused):
        egress_check("https://someone.attacker.example", app.config.egress_hosts)
    assert fake_system.creates == 0


def test_cuj4_gate_green_red_and_unqualified_start(live_cfg_dir, fake_system, capsys):
    assert cli.main(["--config", str(live_cfg_dir), "gate", "test-agent"]) == 0
    assert "10/10" in capsys.readouterr().out
    # make one recorded answer wrong in the tmp copy -> 9/10 < 1.0
    cfg = load_config(live_cfg_dir)
    rec = next(p for p in sorted(cfg.recorded_dir.glob("*.json")) if "Desk lamp" in p.read_text())
    data = json.loads(rec.read_text(encoding="utf-8"))
    data["tool_calls"][0]["input"]["amount"] = "99.99"
    rec.write_text(json.dumps(data), encoding="utf-8")
    assert cli.main(["--config", str(live_cfg_dir), "gate", "test-agent"]) == 1
    # a prompt change invalidates the earlier green run
    prompt = live_cfg_dir / "prompts" / "test-agent.md"
    prompt.write_text(prompt.read_text(encoding="utf-8") + "New rule.\n", encoding="utf-8")
    with pytest.raises(Unqualified):
        build(
            live_cfg_dir, FakeSecretProvider({"fixture-token": fake_system.token}), ["test-agent"]
        )


def test_cuj5_intent_write_fails_before_the_call(app, fake_system, monkeypatch):
    run = app.runtime.handle("test-agent", "svc:test-agent", _doc(app, "create.txt"))
    real = app.audit.write_intent

    def failing(event):
        if event.domain == "action":
            raise AuditUnavailable("disk gone")
        return real(event)

    monkeypatch.setattr(app.audit, "write_intent", failing)
    _approve(app, _pending(app, run.run_id))
    final = app.store.get_run(run.run_id)
    assert (final.state, final.reason_code) == (S.NEEDS_PERSON, "audit_unavailable")
    assert fake_system.creates == 0


def test_cuj5_outcome_write_fails_then_reconcile(app, fake_system, monkeypatch):
    run = app.runtime.handle("test-agent", "svc:test-agent", _doc(app, "create.txt"))
    real = app.audit._write

    def failing(event):
        if event.operation == "result":
            raise OSError("disk gone")
        return real(event)

    monkeypatch.setattr(app.audit, "_write", failing)
    _approve(app, _pending(app, run.run_id))
    assert app.store.get_run(run.run_id).state == S.SUCCEEDED
    assert len(list(app.audit.outbox.glob("*.json"))) == 1
    monkeypatch.setattr(app.audit, "_write", real)
    assert app.audit.reconcile() == 1
    assert ("action", "result") in [(e.domain, e.operation) for e in app.audit.events(run.run_id)]


def test_cuj6_timeout_then_lookup_continues(app, fake_system):
    fake_system.timeout_once_on_create = True
    run = app.runtime.handle("test-agent", "svc:test-agent", _doc(app, "create.txt"))
    _approve(app, _pending(app, run.run_id))
    assert app.store.get_run(run.run_id).state == S.SUCCEEDED
    assert fake_system.creates == 1


def test_cuj6_lookup_fails_needs_a_person(app, fake_system):
    fake_system.timeout_once_on_create = True
    fake_system.fail_lookups = True
    run = app.runtime.handle("test-agent", "svc:test-agent", _doc(app, "create.txt"))
    _approve(app, _pending(app, run.run_id))
    final = app.store.get_run(run.run_id)
    assert (final.state, final.reason_code) == (S.NEEDS_PERSON, "lookup_failed")
    assert fake_system.creates == 1


def test_verify_fails_rolls_back(app, fake_system):
    fake_system.verify_mismatch = True
    run = app.runtime.handle("test-agent", "svc:test-agent", _doc(app, "create.txt"))
    _approve(app, _pending(app, run.run_id))
    final = app.store.get_run(run.run_id)
    assert (final.state, final.reason_code) == (S.ROLLED_BACK, "verify_failed")
    assert fake_system.records == {}


def test_sign_off_denied_and_read_only_runs_without_approval(app, fake_system):
    run = app.runtime.handle("test-agent", "svc:test-agent", _doc(app, "delete.txt"))
    assert (run.state, run.reason_code) == (S.DENIED, "class.sign_off.no_stepup")
    # seed a record, then a read-only lookup runs straight through
    create = app.runtime.handle("test-agent", "svc:test-agent", _doc(app, "create.txt"))
    _approve(app, _pending(app, create.run_id))
    look = app.runtime.handle("test-agent", "svc:test-agent", _doc(app, "lookup.txt"))
    assert look.state == S.SUCCEEDED
    assert not [r for r in app.store._approvals.values() if r.run_id == look.run_id]


@pytest.mark.parametrize("action", ["stop", "reset"])
def test_cli_kill_switch_refused_without_shared_store(cfg_dir, capsys, action):
    """A separate CLI process cannot reach the memory store: it must refuse, not claim success."""
    assert cli.main(["--config", str(cfg_dir), "limits", action, "--by", "user:a"]) == 2
    assert "refused" in capsys.readouterr().err
    assert not (cfg_dir / "audit" / "index.jsonl").exists()


def test_in_process_reset_is_audited(app):
    app.limits.stop(by="user:a")
    app.limits.reset(by="user:a")
    ops = [(e.operation, e.principal) for e in app.audit.events("-")]
    assert ops == [("stop", "user:a"), ("reset", "user:a")]


def test_golden_input_ref_cannot_escape_inputs_dir(cfg_dir):
    from hadavin_sdk.config import ConfigError

    golden = cfg_dir.parent / "golden" / "test-agent.jsonl"
    golden.write_text(
        '{"id": "x", "input_ref": "../config/config.yaml", "expected": {}}\n', encoding="utf-8"
    )
    with pytest.raises(ConfigError, match="escapes"):
        _qualify(cfg_dir)


def test_prompt_file_cannot_escape_config_dir(cfg_dir):
    import yaml

    from hadavin_sdk.config import ConfigError

    path = cfg_dir / "agents.yaml"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    data[0]["prompt_file"] = "../inputs/create.txt"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    with pytest.raises(ConfigError, match="escapes"):
        load_registry(load_config(cfg_dir))
