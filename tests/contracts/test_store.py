"""Store suite: the public Store Protocol only, over every registered store kind (P2 adds postgres)."""

import threading
import time
from datetime import date, timedelta
from decimal import Decimal

import pytest

from hadavin_sdk.models import (
    ApprovalDecision,
    ApprovalRequest,
    ChainStep,
    DeadLetter,
    GateDecision,
    KillSwitch,
    Run,
    RunState,
    TickState,
    now,
)
from hadavin_sdk.store.protocol import NotFound, StaleState

S = RunState


def _run(store, state=S.RECEIVED):
    run = Run(agent_id="a", principal_id="p", trigger_kind="event", trigger_ref="t")
    store.create_run(run)
    if state is not S.RECEIVED:
        store.transition(run.run_id, S.RECEIVED, state)
    return store.get_run(run.run_id)


def _request(store, status="PENDING", expires_in=timedelta(minutes=1)):
    req = ApprovalRequest(
        run_id="run-x",
        plan_hash="h",
        risk_class="reversible",
        chain_id="c",
        steps=[ChainStep(approver_ids=["user:a"], timeout_s=60)],
        status=status,
        step_expires_at=now() + expires_in,
        requested_by="svc:a",
        summary="s",
    )
    store.save_approval_request(req)
    return req


def test_runs_are_copies_and_unknown_is_not_found(store):
    run = _run(store)
    got = store.get_run(run.run_id)
    got.state = S.SUCCEEDED
    assert store.get_run(run.run_id).state == S.RECEIVED
    with pytest.raises(NotFound):
        store.get_run("run-missing")


def test_transition_is_compare_and_set(store):
    run = _run(store)
    moved = store.transition(run.run_id, S.RECEIVED, S.WORKING, "why")
    assert (moved.state, moved.reason_code) == (S.WORKING, "why")
    with pytest.raises(StaleState):
        store.transition(run.run_id, S.RECEIVED, S.WORKING)


def test_add_cost_accumulates_and_unknown_run_is_not_found(store):
    run = _run(store)
    store.add_cost(run.run_id, Decimal("0.25"))
    store.add_cost(run.run_id, Decimal("0.50"))
    assert store.get_run(run.run_id).cost_usd == Decimal("0.75")
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


def test_approval_request_update_is_compare_and_set(store):
    req = _request(store)
    store.update_approval_request(req.model_copy(update={"status": "APPROVED"}), "PENDING", 0)
    assert store.get_approval_request(req.approval_id).status == "APPROVED"
    with pytest.raises(StaleState):
        store.update_approval_request(req.model_copy(update={"status": "REJECTED"}), "PENDING", 0)
    with pytest.raises(NotFound):
        store.get_approval_request("apr-missing")


def test_due_approvals_are_pending_and_expired(store):
    due = _request(store, expires_in=timedelta(seconds=-1))
    _request(store)
    _request(store, status="APPROVED", expires_in=timedelta(seconds=-1))
    assert [r.approval_id for r in store.list_due_approvals(now())] == [due.approval_id]


def test_get_approval_decision_returns_latest_or_none(store):
    assert store.get_approval_decision("apr-x") is None

    def decision(step, verdict):
        return ApprovalDecision(
            approval_id="apr-x",
            plan_hash="h",
            step=step,
            decision=verdict,
            approver_id="user:a",
            channel="fake",
        )

    store.save_approval_decision(decision(0, "reject"))
    store.save_approval_decision(decision(1, "approve"))
    assert store.get_approval_decision("apr-x").decision == "approve"
    with pytest.raises(StaleState):  # one decision per step: a racing or replayed one is refused
        store.save_approval_decision(decision(1, "reject"))
    assert store.get_approval_decision("apr-x").decision == "approve"


def test_gate_decision_is_written_once(store):
    d = GateDecision(run_id="run-g", plan_hash="h", outcome="allow", rule_id="r")
    store.save_gate_decision(d)
    with pytest.raises(StaleState):
        store.save_gate_decision(d.model_copy(update={"outcome": "deny"}))
    assert store.get_gate_decision("run-g").outcome == "allow"


def test_tick_state_round_trip(store):
    assert store.get_tick_state("sweep") is None
    at = now()
    store.save_tick_state(TickState(step="sweep", last_run_at=at, last_error="X: y"))
    store.save_tick_state(TickState(step="sweep", last_run_at=at, last_ok_at=at))
    got = store.get_tick_state("sweep")
    assert (got.last_run_at, got.last_ok_at, got.last_error) == (at, at, None)


def test_sent_at_and_channel_ref_round_trip(store):
    req = _request(store)
    assert (req.sent_at, req.channel_ref) == (None, None)
    sent = req.model_copy(update={"sent_at": now(), "channel_ref": "ts-1"})
    store.update_approval_request(sent, "PENDING", 0)
    assert store.get_approval_request(req.approval_id).channel_ref == "ts-1"


def test_list_approvals_by_status(store):
    pending, done = _request(store), _request(store)
    store.update_approval_request(done.model_copy(update={"status": "APPROVED"}), "PENDING", 0)
    assert [r.approval_id for r in store.list_approvals({"PENDING"})] == [pending.approval_id]
    assert {r.approval_id for r in store.list_approvals({"PENDING", "APPROVED"})} == {
        pending.approval_id,
        done.approval_id,
    }
    assert store.list_approvals({"EXPIRED"}) == []


def test_spend_day_and_month_totals(store):
    today = now().date()
    assert store.spend_totals("a", today) == (Decimal(0), Decimal(0))
    assert store.spend_totals("a", today) == (Decimal(0), Decimal(0))  # a read writes nothing
    store.add_spend("a", today, Decimal("0.40"))
    assert store.add_spend("a", today, Decimal("0.10")) == (Decimal("0.50"), Decimal("0.50"))
    _, month = store.add_spend("a", today - timedelta(days=40), Decimal(5))
    assert month == Decimal(5)
    assert store.spend_totals("a", today) == (Decimal("0.50"), Decimal("0.50"))


def test_month_total_spans_days_and_money_is_exact(store):
    d1, d2 = date(2026, 3, 10), date(2026, 3, 11)
    store.add_spend("m", d1, Decimal("0.00108225"))
    day, month = store.add_spend("m", d2, Decimal("0.5"))
    assert (day, month) == (Decimal("0.5"), Decimal("0.50108225"))
    assert store.spend_totals("m", d1) == (Decimal("0.00108225"), Decimal("0.50108225"))
    run = _run(store)
    store.add_cost(run.run_id, Decimal("0.00108225"))
    assert store.get_run(run.run_id).cost_usd == Decimal("0.00108225")


def test_dead_letters_and_kill_switch(store):
    store.add_dead_letter(DeadLetter(run_id="run-x", reason="r", errors=["e"]))
    assert [d.reason for d in store.list_dead_letters("run-x")] == ["r"]
    assert store.list_dead_letters("run-y") == []
    assert store.get_kill_switch().on is False
    store.set_kill_switch(KillSwitch(on=True, by="user:a"))
    assert (store.get_kill_switch().on, store.get_kill_switch().by) == (True, "user:a")


def test_two_threads_racing_one_cas_exactly_one_wins(store):
    run = _run(store)
    results = []
    gate = threading.Barrier(2)

    def race():
        gate.wait()
        try:
            store.transition(run.run_id, S.RECEIVED, S.WORKING)
            results.append("won")
        except StaleState:
            results.append("stale")

    threads = [threading.Thread(target=race) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(results) == ["stale", "won"]


def test_record_decision_is_atomic(store):
    req = _request(store)
    d = ApprovalDecision(
        approval_id=req.approval_id,
        plan_hash="h",
        step=0,
        decision="reject",
        approver_id="user:a",
        channel="fake",
    )
    approved = req.model_copy(update={"status": "APPROVED"})
    with pytest.raises(StaleState):  # the request is not at step 1: nothing is written
        store.record_decision(d, approved, "PENDING", 1)
    assert store.get_approval_decision(req.approval_id) is None
    assert store.get_approval_request(req.approval_id).status == "PENDING"
    store.record_decision(d, approved, "PENDING", 0)
    assert store.get_approval_decision(req.approval_id).decision == "reject"
    with pytest.raises(StaleState):  # a second click on the same step
        store.record_decision(d, approved, "PENDING", 0)
