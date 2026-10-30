"""Regression tests for the CodeRabbit review of PR #3 (one test per finding)."""

from datetime import timedelta

import pytest
import yaml

from hadavin_sdk.actions.executor import Executor
from hadavin_sdk.actions.secrets import FakeSecretProvider
from hadavin_sdk.audit import AuditUnavailable, LocalDirSink
from hadavin_sdk.config import ConfigError, load_config
from hadavin_sdk.models import AuditEvent, RunState, ToolCall
from hadavin_sdk.registry import load_registry
from tests.test_executor import _approved, _plan
from tests.test_s5_runtime import build
from tests.test_s6_approvals import _d, _request, env  # noqa: F401 - env is a fixture

S = RunState


def _edit(path, fn):
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    data = fn(data) or data
    path.write_text(yaml.safe_dump(data), encoding="utf-8")


@pytest.fixture
def ex(live_cfg_dir, fake_system):
    reg = load_registry(load_config(live_cfg_dir))
    return Executor(reg, FakeSecretProvider({"fixture-token": fake_system.token}), timeout_s=0.5)


# contract.py: unsupported schema types fail at load, not in the gate
@pytest.mark.parametrize("bad", [{"type": "number"}, {"type": "string", "format": "x"}])
def test_unsupported_schema_rejected_at_load(cfg_dir, bad):
    _edit(
        cfg_dir / "actions" / "lookup_record.yaml",
        lambda d: d["input_schema"]["properties"].update(id=bad),
    )
    with pytest.raises(ConfigError, match="unsupported"):
        load_registry(load_config(cfg_dir))


# executor.py: a redirect must not carry the token to another URL
def test_redirect_refused_and_token_not_forwarded(ex, fake_system):
    fake_system.redirect_create = True
    plan = _plan()
    result = ex.execute(plan, *_approved(plan))
    assert (result.outcome, result.error_code) == ("failed", "http_302")
    assert fake_system.stolen_auth == []


# executor.py: path values are percent-encoded
def test_path_values_are_encoded():
    method, path = Executor._path("GET /records/{id}", {"id": "../admin?force=1"}, "k")
    assert (method, path) == ("GET", "/records/..%2Fadmin%3Fforce%3D1")


# executor.py: a dropped connection or a non-JSON 2xx after the request is sent -> lookup
@pytest.mark.parametrize("switch", ["drop_after_create", "garbage_after_create"])
def test_reply_lost_after_send_is_looked_up(ex, fake_system, switch):
    setattr(fake_system, switch, True)
    plan = _plan()
    result = ex.execute(plan, *_approved(plan))
    assert (result.outcome, result.external_ref) == ("succeeded", "rec-001")
    assert fake_system.creates == 1


# requests.py: a decision after the step deadline is refused even before the sweep runs
def test_decision_after_deadline_refused(env):  # noqa: F811 - pytest fixture argument
    appr, _, decided, clock = env
    req = _request(appr)
    clock.t += timedelta(hours=4)
    assert appr.decide(_d(req, "user:a")) == (False, "step_expired")
    assert decided == []


def _event():
    return AuditEvent(run_id="r", domain="d", operation="o", principal="p", source="s")


# local_dir.py: an object with no index line is completed, not silently dropped
def test_half_written_event_is_completed(tmp_path):
    sink = LocalDirSink(tmp_path)
    ev = _event()
    sink.objects.mkdir(parents=True)
    (sink.objects / f"{ev.event_id}.json").write_bytes(ev.model_dump_json().encode())
    assert sink.write_outcome(ev) == f"{ev.event_id}.json"
    assert [e.event_id for e in sink.events()] == [ev.event_id]
    assert sink.verify_object(f"{ev.event_id}.json")


# local_dir.py: write_outcome never raises, even when the outbox is unwritable
def test_write_outcome_never_raises(tmp_path, monkeypatch):
    sink = LocalDirSink(tmp_path)
    real = sink._write

    def boom(event):
        raise OSError("disk gone")

    monkeypatch.setattr(sink, "_write", boom)
    (tmp_path / "outbox").write_text("a file where the folder should be", encoding="utf-8")
    assert sink.write_outcome(_event()) is None
    monkeypatch.setattr(sink, "_write", real)
    assert sink.reconcile() == 1
    assert len(sink.events()) == 1


# config.py: plain http only to loopback
@pytest.mark.parametrize(
    "url,ok",
    [
        ("https://erp.example.test", True),
        ("http://127.0.0.1:9", True),
        ("http://localhost:9", True),
        ("http://erp.example.test", False),
        ("ftp://127.0.0.1", False),
    ],
)
def test_base_url_scheme(cfg_dir, url, ok):
    _edit(cfg_dir / "config.yaml", lambda d: d["systems"]["fixture-records"].update(base_url=url))
    if ok:
        load_config(cfg_dir)
    else:
        with pytest.raises(ConfigError, match="https"):
            load_config(cfg_dir)


# config.py: every start-up failure is a ConfigError
def test_missing_config_dir_env_is_config_error(monkeypatch):
    monkeypatch.delenv("HADAVIN_CONFIG_DIR", raising=False)
    with pytest.raises(ConfigError):
        load_config()


def test_non_mapping_yaml_is_config_error(cfg_dir):
    (cfg_dir / "egress.yaml").write_text("- just\n- a list\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="mapping"):
        load_config(cfg_dir)


# limits.py: stop works with the audit store down; reset does not
def test_stop_works_when_audit_is_down(cfg_dir, monkeypatch):
    rt, _ = build(cfg_dir)

    def down(event):
        raise OSError("disk gone")

    monkeypatch.setattr(rt.audit, "_write", down)
    rt.limits.stop(by="user:a")
    assert "kill_switch" in rt.limits.blocked("test-agent")
    with pytest.raises(AuditUnavailable):
        rt.limits.reset(by="user:a")
    assert "kill_switch" in rt.limits.blocked("test-agent")


# registry.py: duplicate or missing ids fail at start-up
def test_duplicate_principal_id_rejected(cfg_dir):
    _edit(
        cfg_dir / "principals.yaml",
        lambda d: d + [{"id": "user:a", "kind": "person", "rights": ["delete_record"]}],
    )
    with pytest.raises(ConfigError, match="duplicate"):
        load_registry(load_config(cfg_dir))


def test_missing_id_is_config_error(cfg_dir):
    _edit(cfg_dir / "chains.yaml", lambda d: d + [{"steps": []}])
    with pytest.raises(ConfigError):
        load_registry(load_config(cfg_dir))


# agent_loop.py: bad model proposals never strand a run
@pytest.mark.parametrize(
    "call",
    [
        ToolCall(name="create_draft_record", input={"title": "Desk", "amount": 120.0}),
        ToolCall(name="lookup_record", input={"id": 42}),
    ],
)
def test_bad_proposal_needs_a_person(cfg_dir, call):
    rt, _ = build(cfg_dir)
    from hadavin_sdk.models import Run

    run = Run(
        agent_id="test-agent", principal_id="svc:test-agent", trigger_kind="event", trigger_ref="t"
    )
    rt.store.create_run(run)
    rt._to(run, S.WORKING)
    final = rt._submit(run, call)
    assert (final.state, final.reason_code) == (S.NEEDS_PERSON, "invalid_proposal")


# agent_loop.py: hook exceptions never leave EXECUTING or VERIFYING
@pytest.mark.parametrize("which", ["execute", "verify", "rollback"])
def test_hook_exceptions_end_in_a_final_state(cfg_dir, which):
    from hadavin_sdk.models import RunResult
    from hadavin_sdk.runtime.agent_loop import Hooks

    def boom(*a, **k):
        raise RuntimeError("hook failed")

    hooks = Hooks(
        request_approval=None,
        execute=lambda p, d, a: RunResult(outcome="succeeded", external_ref="rec-001"),
        verify=lambda p, r: False,
        rollback=lambda p, r: RunResult(outcome="failed", error_code="x"),
    )
    setattr(hooks, which, boom)
    rt, cfg = build(cfg_dir, hooks)
    run = rt.handle("test-agent", "svc:test-agent", (cfg.inputs_dir / "create.txt").read_bytes())
    assert run.state == S.NEEDS_PERSON  # approvals not configured in this harness
    # drive execution directly from PLAN_READY-equivalent: re-run the approved path
    rt.store._runs[run.run_id] = rt.store.get_run(run.run_id).model_copy(
        update={"state": S.WAITING_FOR_APPROVAL}
    )
    final = rt.execute(run.run_id)
    assert final.state == S.NEEDS_PERSON
