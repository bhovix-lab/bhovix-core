"""Slice 2 P1a: slice 1 fixes (design v3 §12.10). The Store additions' tests moved to the Store contract
suite, tests/contracts/test_store.py, in P1b."""

import logging
import time
from decimal import Decimal

import pytest
import yaml

from hadavin_sdk.actions.executor import Executor
from hadavin_sdk.actions.secrets import FakeSecretProvider
from hadavin_sdk.config import load_config
from hadavin_sdk.guard.injection import injection_check
from hadavin_sdk.llm.protocol import ProviderExhausted
from hadavin_sdk.models import (
    RunState,
    Verdict,
    now,
)
from hadavin_sdk.registry import load_registry
from tests.test_executor import _approved, _plan
from tests.test_s5_runtime import build

S = RunState
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
        update={
            "backends": reg.config.backends.model_copy(
                update={"llm": reg.config.backends.llm.model_copy(update={"kind": "bedrock"})}
            )
        }
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
