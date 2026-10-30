"""Slice 2 P7: `tick` (v5 contract), record-only decisions, resend, stuck runs, Slack channel, receiver."""

import hashlib
import hmac
import json
import threading
import time
import urllib.request
from datetime import timedelta
from urllib.parse import urlencode

import pytest

from hadavin_sdk import cli
from hadavin_sdk.actions.secrets import FakeSecretProvider
from hadavin_sdk.app import build
from hadavin_sdk.approvals import FakeChannel
from hadavin_sdk.approvals.receiver import MAX_BODY, handle_slack_action, serve
from hadavin_sdk.approvals.slack_channel import SlackChannel, SlackError
from hadavin_sdk.backends import make
from hadavin_sdk.backends.table import SlackSettings
from hadavin_sdk.config import ConfigError
from hadavin_sdk.models import ApprovalDecision, RunState
from hadavin_sdk.runtime import tick
from hadavin_sdk.runtime.tick import TickStep, run_tick
from tests.conftest import qualify
from tests.fixtures.fake_slack import FakeSlack
from tests.test_cuj import _doc, _pending

S = RunState
SIG = "sig" + "-p7-test"  # built from parts
TOKEN = "xoxb" + "-p7-fake"  # built from parts


@pytest.fixture
def app(live_cfg_dir, fake_system):
    from hadavin_sdk.config import load_config
    from hadavin_sdk.registry import load_registry

    qualify(load_registry(load_config(live_cfg_dir)))
    return build(
        live_cfg_dir,
        ["test-agent"],
        secrets=FakeSecretProvider({"fixture-token": fake_system.token}),
        channel=FakeChannel(SIG),
        timeout_s=0.5,
    )


def _callback(req, user, ts, verdict="approve", secret=SIG):
    value = f"{req.approval_id}|{req.plan_hash}|{req.current_step}|{verdict}"
    body = urlencode({"payload": json.dumps({"user": {"id": user}, "actions": [{"value": value}]})})
    body = body.encode()
    sig = hmac.new(secret.encode(), f"v0:{ts}:".encode() + body, hashlib.sha256).hexdigest()
    return {"X-Slack-Request-Timestamp": str(ts), "X-Slack-Signature": "v0=" + sig}, body


def _waiting(app):
    run = app.runtime.handle("test-agent", "svc:test-agent", _doc(app, "create.txt"))
    assert app.store.get_run(run.run_id).state == S.WAITING_FOR_APPROVAL
    return run, _pending(app, run.run_id)


def _record(app, req, approver="user:a", verdict="approve"):
    return app.approvals.decide(
        ApprovalDecision(
            approval_id=req.approval_id,
            plan_hash=req.plan_hash,
            step=req.current_step,
            decision=verdict,
            approver_id=approver,
            channel="fake",
        ),
        record_only=True,
    )


# --- tick contract ---------------------------------------------------------------------------------------


def test_steps_order_and_heartbeat_last(app, caplog):
    assert [s.name for s in tick.STEPS] == ["sweep", "reconcile", "stuck", "checkpoint"]
    caplog.set_level("INFO", logger="hadavin_sdk.tick")
    assert run_tick(app) == 0
    assert "tick ok=True failed=-" in caplog.text
    assert app.store.get_tick_state("heartbeat").last_error is None


def test_one_failing_step_lets_the_others_run_and_exits_1(app, caplog):
    caplog.set_level("INFO", logger="hadavin_sdk.tick")
    ran = []
    secret = "AKIA" + "IOSFODNN7EXAMPLE"

    def boom(ctx):
        raise RuntimeError(f"broken with {secret}\nsecond line")

    steps = [TickStep("first", 0, boom), TickStep("second", 0, lambda ctx: ran.append("second"))]
    assert run_tick(app, steps=steps) == 1
    assert ran == ["second"]
    state = app.store.get_tick_state("first")
    assert state.last_error.startswith("RuntimeError: ") and secret not in state.last_error
    assert state.last_ok_at is None and app.store.get_tick_state("second").last_error is None
    assert "step=first error_kind=RuntimeError" in caplog.text and secret not in caplog.text
    assert "failed=first" in caplog.text


def test_store_unreachable_exits_3_before_any_step(app, monkeypatch):
    ran = []

    def down(step):
        raise OSError("store down")

    monkeypatch.setattr(app.store, "get_tick_state", down)
    assert run_tick(app, steps=[TickStep("x", 0, lambda ctx: ran.append(1))]) == 3
    assert ran == []


def test_every_s_is_honoured_with_an_injected_clock(app):
    ran = []
    step = [TickStep("hourly", 3600, lambda ctx: ran.append(ctx.now))]
    t0 = app.approvals.clock()
    for at in (t0, t0 + timedelta(minutes=30), t0 + timedelta(minutes=61)):
        assert run_tick(app, now=at, steps=step) == 0
    assert ran == [t0, t0 + timedelta(minutes=61)]


# --- record-only decisions and reconcile -----------------------------------------------------------------


def test_record_only_decision_runs_on_the_next_tick(app, fake_system):
    run, req = _waiting(app)
    assert _record(app, req) == (True, "approved")
    assert app.store.get_run(run.run_id).state == S.WAITING_FOR_APPROVAL  # nothing ran yet
    assert fake_system.creates == 0
    assert run_tick(app) == 0
    assert app.store.get_run(run.run_id).state == S.SUCCEEDED
    assert run_tick(app) == 0  # a second tick changes nothing
    assert fake_system.creates == 1


def test_two_concurrent_ticks_execute_once(app, fake_system):
    run, req = _waiting(app)
    _record(app, req)
    codes, gate = [], threading.Barrier(2)

    def one():
        gate.wait()
        codes.append(run_tick(app))

    threads = [threading.Thread(target=one) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert app.store.get_run(run.run_id).state == S.SUCCEEDED
    assert fake_system.creates == 1
    assert codes == [0, 0]


def test_rejected_is_reconciled(app):
    run, req = _waiting(app)
    _record(app, req, verdict="reject")
    assert run_tick(app) == 0
    assert app.store.get_run(run.run_id).state == S.REJECTED


def test_expired_is_reconciled(app):
    run, req = _waiting(app)
    later = app.approvals.clock() + timedelta(days=30)  # past every step's timeout
    for _ in req.steps:
        assert run_tick(app, now=later) == 0
        later += timedelta(days=30)
    assert app.store.get_run(run.run_id).state == S.EXPIRED


def test_racing_decisions_on_one_step_keep_one(app):
    _, req = _waiting(app)
    assert _record(app, req)[0] is True
    assert _record(app, req, verdict="reject") == (False, "not_pending")
    assert app.store.get_approval_decision(req.approval_id).decision == "approve"


# --- channel send failures --------------------------------------------------------------------------------


def test_failed_send_is_resent_by_tick(app):
    channel = app.approvals.channel
    real = channel.send

    def down(req, approvers):
        raise ConnectionError("channel down")

    channel.send = down
    _run, req = _waiting(app)
    assert app.store.get_approval_request(req.approval_id).sent_at is None
    channel.send = real
    assert run_tick(app) == 0
    sent = app.store.get_approval_request(req.approval_id)
    assert sent.sent_at is not None and sent.channel_ref
    assert [s[0] for s in channel.sent] == [req.approval_id]


# --- stuck runs -------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "state,reason",
    [
        (S.RECEIVED, "interrupted"),
        (S.EXECUTING, "outcome_unknown"),
        (S.VERIFYING, "verify_interrupted"),
    ],
)
def test_stuck_runs_go_to_a_person(app, state, reason):
    from hadavin_sdk.models import Run

    run = Run(
        agent_id="test-agent", principal_id="svc:test-agent", trigger_kind="event", trigger_ref="t"
    )
    app.store.create_run(run)
    old = app.approvals.clock() - timedelta(hours=6)
    app.store._runs[run.run_id] = run.model_copy(update={"state": state, "updated_at": old})
    fresh = Run(
        agent_id="test-agent", principal_id="svc:test-agent", trigger_kind="event", trigger_ref="t"
    )
    app.store.create_run(fresh)
    app.store._runs[fresh.run_id] = fresh.model_copy(update={"state": state})
    assert run_tick(app) == 0
    got = app.store.get_run(run.run_id)
    assert (got.state, got.reason_code) == (S.NEEDS_PERSON, reason)
    assert app.store.get_run(fresh.run_id).state == state  # recent: left alone
    assert any(e.error_code == reason for e in app.audit.events(run.run_id))


def test_stuck_threshold_follows_the_agent_and_llm_settings(app):
    agent = app.registry.agents["test-agent"]
    assert (
        tick.stuck_after_s(app, "test-agent") == agent.max_steps * 60 * 1 + 60
    )  # fake llm: defaults


# --- receiver ---------------------------------------------------------------------------------------------


def test_receiver_records_and_never_executes(app, fake_system):
    run, req = _waiting(app)
    now = int(app.approvals.clock().timestamp())
    assert handle_slack_action(app.approvals, *_callback(req, "U1", now, secret=SIG[::-1])) == (
        401,
        b"",
    )
    assert handle_slack_action(app.approvals, {}, b"x" * (MAX_BODY + 1)) == (413, b"")
    # a verified click by someone who is not an approver: 200, recorded as refused, nothing decided
    assert handle_slack_action(app.approvals, *_callback(req, "U1", now))[0] == 200
    assert app.store.get_approval_request(req.approval_id).status == "PENDING"
    p = app.registry.principals
    from hadavin_sdk.identity import Principal

    p["slack:UAPPROVER"] = Principal(
        id="slack:UAPPROVER", kind="person", approver_of=[req.chain_id]
    )
    req.steps[0].approver_ids.append("slack:UAPPROVER")
    app.store.save_approval_request(req)
    assert handle_slack_action(app.approvals, *_callback(req, "UAPPROVER", now)) == (200, b"")
    assert app.store.get_approval_request(req.approval_id).status == "APPROVED"
    assert (
        app.store.get_run(run.run_id).state == S.WAITING_FOR_APPROVAL and fake_system.creates == 0
    )
    run_tick(app)
    assert fake_system.creates == 1


def test_dev_server_answers_over_http(app):
    _, req = _waiting(app)
    server = serve(app.approvals, port=0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{server.server_address[1]}"
        headers, body = _callback(req, "U1", int(time.time()), secret=SIG[::-1])
        r = urllib.request.Request(  # noqa: S310 - loopback test server
            url + "/slack/actions", data=body, headers=headers, method="POST"
        )
        with pytest.raises(urllib.error.HTTPError) as err:
            urllib.request.urlopen(r, timeout=5)  # noqa: S310 - loopback test server
        assert err.value.code == 401
        r = urllib.request.Request(url + "/other", data=b"", method="POST")  # noqa: S310 - loopback
        with pytest.raises(urllib.error.HTTPError) as err:
            urllib.request.urlopen(r, timeout=5)  # noqa: S310 - loopback test server
        assert err.value.code == 404
    finally:
        server.shutdown()
        server.server_close()


# --- slack channel ----------------------------------------------------------------------------------------


@pytest.fixture
def fake_slack():
    api = FakeSlack().start()
    yield api
    api.stop()


def test_slack_send_and_update(app, fake_slack):
    _, req = _waiting(app)
    ch = SlackChannel("C0TEST", TOKEN, SIG, api_base=fake_slack.api_base)
    ts = ch.send(req, ["slack:U1", "user:a"])
    method, body, auth = fake_slack.calls[-1]
    assert (method, body["channel"], auth) == ("chat.postMessage", "C0TEST", f"Bearer {TOKEN}")
    blocks = body["blocks"]
    assert (
        blocks[0]["text"]["type"] == "plain_text"
    )  # no markdown, links or mentions from the summary
    values = [e["value"] for e in blocks[2]["elements"]]
    assert values == [f"{req.approval_id}|{req.plan_hash}|0|{v}" for v in ("approve", "reject")]
    assert "<@U1>" in blocks[1]["elements"][0]["text"]
    ch.update(req.model_copy(update={"status": "APPROVED", "channel_ref": ts}))
    method, body, _ = fake_slack.calls[-1]
    assert (method, body["ts"]) == ("chat.update", ts) and len(body["blocks"]) == 2  # buttons gone
    n = len(fake_slack.calls)
    ch.update(req.model_copy(update={"channel_ref": None}))  # never sent: nothing to update
    assert len(fake_slack.calls) == n


def test_slack_error_raises_with_the_code_only(fake_slack):
    fake_slack.fail_with = "channel_not_found"
    ch = SlackChannel("C0TEST", TOKEN, SIG, api_base=fake_slack.api_base)
    with pytest.raises(SlackError, match="chat.postMessage: channel_not_found") as err:
        ch.notify("user:a", "hello")
    assert TOKEN not in str(err.value)


def test_slack_factory_resolves_its_secrets_and_refuses_http():
    settings = SlackSettings(
        kind="slack",
        channel_id="C0TEST",
        signing_secret_name="slack-sig",  # noqa: S106 - a name
        bot_token_secret_name="slack-bot",  # noqa: S106 - a name
    )
    secrets = FakeSecretProvider({"slack-sig": SIG, "slack-bot": TOKEN})
    ch = make("channel", settings, secrets)
    assert (ch._token, ch._secret, ch.api_base) == (TOKEN, SIG, "https://slack.com/api")
    with pytest.raises(ConfigError, match="https"):
        make("channel", settings.model_copy(update={"api_base": "http://slack.example"}), secrets)


# --- CLI --------------------------------------------------------------------------------------------------


def test_cli_tick_exit_codes(cfg_dir, monkeypatch, capsys):
    from hadavin_sdk.config import load_config
    from hadavin_sdk.registry import load_registry

    qualify(load_registry(load_config(cfg_dir)))
    monkeypatch.setattr(
        "hadavin_sdk.backends.builtin.fake_secrets",
        lambda settings, deps: FakeSecretProvider({"fixture-token": "t"}),
    )
    assert cli.main(["--config", str(cfg_dir), "tick"]) == 0
    (cfg_dir / "config.yaml").write_text("environment: nowhere\n", encoding="utf-8")
    assert cli.main(["--config", str(cfg_dir), "tick"]) == 2
    assert "config error" in capsys.readouterr().err


def test_cli_tick_store_unreachable_exits_3(cfg_dir, monkeypatch):
    pytest.importorskip("psycopg")
    import yaml

    from hadavin_sdk.config import load_config
    from hadavin_sdk.registry import load_registry

    qualify(load_registry(load_config(cfg_dir)))
    path = cfg_dir / "config.yaml"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    data["backends"]["store"] = {"kind": "postgres", "dsn_secret_name": "pg-dsn"}
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    closed = "postgresql://nobody@127.0.0.1:1/none"  # nothing listens on port 1
    monkeypatch.setattr(
        "hadavin_sdk.backends.builtin.fake_secrets",
        lambda settings, deps: FakeSecretProvider({"pg-dsn": closed, "fixture-token": "t"}),
    )
    assert cli.main(["--config", str(cfg_dir), "tick"]) == 3
