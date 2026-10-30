"""S6: approval requests, decisions, escalation sweep, Slack signature check."""

import hashlib
import hmac
from datetime import UTC, datetime, timedelta

import pytest

from hadavin_sdk.approvals import Approvals, FakeChannel
from hadavin_sdk.approvals.slack import verify
from hadavin_sdk.audit import LocalDirSink
from hadavin_sdk.config import load_config
from hadavin_sdk.models import ApprovalDecision, GateDecision, Plan, Target
from hadavin_sdk.registry import load_registry
from hadavin_sdk.store import MemoryStore

T0 = datetime(2026, 10, 30, 9, 0, tzinfo=UTC)


class Clock:
    def __init__(self):
        self.t = T0

    def __call__(self):
        return self.t


@pytest.fixture
def env(cfg_dir):
    cfg = load_config(cfg_dir)
    reg = load_registry(cfg)
    decided = []
    clock = Clock()
    channel = FakeChannel()
    appr = Approvals(
        MemoryStore(),
        LocalDirSink(cfg.audit_dir),
        reg,
        channel,
        lambda run_id, status, d: decided.append((run_id, status)),
        clock,
    )
    return appr, channel, decided, clock


def _plan(inputs=None):
    return Plan(
        run_id="run-1",
        agent_id="test-agent",
        action_id="create_draft_record",
        action_version=1,
        risk_class="reversible",
        inputs=inputs or {"title": "Desk", "amount": "12.50"},
        target=Target(system="fixture-records"),
        idempotency_key="run-1:create_draft_record",
        expected_outcome="one draft record",
    )


def _request(appr, plan=None, requested_by="svc:test-agent"):
    plan = plan or _plan()
    gd = GateDecision(
        run_id=plan.run_id, plan_hash=plan.hash(), outcome="needs_approval", rule_id="x"
    )
    return appr.request(plan, gd, requested_by)


def _d(req, approver, step=None, decision="approve", plan_hash=None):
    return ApprovalDecision(
        approval_id=req.approval_id,
        plan_hash=plan_hash or req.plan_hash,
        step=req.current_step if step is None else step,
        decision=decision,
        approver_id=approver,
        channel="fake",
    )


def test_approve_by_current_step_approver(env):
    appr, channel, decided, _ = env
    req = _request(appr)
    assert channel.sent[0][2] == ["user:a"]
    assert appr.decide(_d(req, "user:a")) == (True, "approved")
    assert decided == [("run-1", "APPROVED")]
    assert appr.decide(_d(req, "user:a")) == (False, "not_pending")


def test_reject_is_final(env):
    appr, _, decided, _ = env
    req = _request(appr)
    assert appr.decide(_d(req, "user:a", decision="reject")) == (True, "rejected")
    assert decided == [("run-1", "REJECTED")]


def test_chain_a_b_c_then_expired_and_nothing_runs(env):
    appr, channel, decided, clock = env
    req = _request(appr)
    for expected_approver in ("user:b", "user:c"):
        clock.t += timedelta(hours=4)
        assert appr.sweep() == [req.approval_id]
        assert channel.sent[-1][2] == [expected_approver]
    clock.t += timedelta(hours=4)
    appr.sweep()
    final = appr.store.get_approval_request(req.approval_id)
    assert final.status == "EXPIRED"
    assert decided == [("run-1", "EXPIRED")]  # never APPROVED
    assert channel.notices and channel.notices[0][0] == "svc:test-agent"
    assert "Nothing was run" in channel.notices[0][1]


def test_sweep_before_timeout_does_nothing(env):
    appr, _, _, clock = env
    _request(appr)
    clock.t += timedelta(hours=3, minutes=59)
    assert appr.sweep() == []


def test_old_step_decision_refused(env):
    appr, _, decided, clock = env
    req = _request(appr)
    clock.t += timedelta(hours=4)
    appr.sweep()
    assert appr.decide(_d(req, "user:a", step=0)) == (False, "old_step")
    assert appr.decide(_d(req, "user:a", step=1)) == (False, "not_an_approver_for_this_step")
    assert decided == []


def test_requester_refused(env):
    appr, _, _, _ = env
    req = _request(appr, requested_by="user:a")
    assert appr.decide(_d(req, "user:a")) == (False, "requester_cannot_approve")


def test_plan_hash_mismatch_refused(env):
    appr, _, _, _ = env
    req = _request(appr)
    assert appr.decide(_d(req, "user:a", plan_hash="f" * 64)) == (False, "plan_hash_mismatch")


def test_channel_text_holds_no_seeded_pii(env):
    appr, channel, _, _ = env
    seeded = {"title": "Pay jo.bloggs@example.test BSB 062-000", "amount": "12.50"}
    _request(appr, _plan(seeded))
    text = channel.sent[0][1]
    assert "jo.bloggs@example.test" not in text and "062-000" not in text
    assert "create_draft_record" in text


def test_channel_text_has_no_links(env):
    appr, channel, _, _ = env
    _request(appr, _plan({"title": "see https://evil.example/x now", "amount": "1"}))
    assert "https://" not in channel.sent[0][1]


# --- Slack signature (fixtures built from parts: no real secret) ---------------------------------
SECRET = "test-" + "signing-" + "secret"


def _signed(ts, body, secret=SECRET):
    sig = hmac.new(secret.encode(), f"v0:{ts}:".encode() + body, hashlib.sha256).hexdigest()
    return {"X-Slack-Request-Timestamp": str(ts), "X-Slack-Signature": "v0=" + sig}


def test_slack_valid_signature():
    now_ts = 1_800_000_000
    assert verify(_signed(now_ts, b"payload=1"), b"payload=1", now_ts + 10, SECRET)


def test_slack_forged_signature_refused():
    now_ts = 1_800_000_000
    headers = _signed(now_ts, b"payload=1", secret="wrong" + "-secret")
    assert not verify(headers, b"payload=1", now_ts, SECRET)
    assert not verify(_signed(now_ts, b"payload=1"), b"payload=2", now_ts, SECRET)


def test_slack_stale_request_refused():
    now_ts = 1_800_000_000
    assert not verify(_signed(now_ts, b"p"), b"p", now_ts + 301, SECRET)
    assert not verify({"X-Slack-Request-Timestamp": "abc"}, b"p", now_ts, SECRET)
