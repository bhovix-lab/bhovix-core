"""Slice 2 P5: the llm kinds' wiring outside the contract suite (design 4.3, 12.10)."""

import pytest
import yaml

from hadavin_sdk.config import load_config
from hadavin_sdk.llm import ProviderError, ProviderExhausted
from hadavin_sdk.llm.retry import MAX_DELAY_S, with_retry
from hadavin_sdk.models import RunState
from hadavin_sdk.registry import load_registry
from tests.test_s5_runtime import build


def _llm(cfg_dir, entry):
    path = cfg_dir / "config.yaml"
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    raw["backends"]["llm"] = entry
    path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    return load_registry(load_config(cfg_dir)).config_hash("test-agent")


def test_where_the_model_runs_is_in_the_config_hash(cfg_dir):
    """A backend swap needs a new gate run, and so does a platform or host swap with the same model id."""
    api = _llm(cfg_dir, {"kind": "anthropic", "platform": "api", "api_key_secret_name": "a"})
    vertex = _llm(
        cfg_dir, {"kind": "anthropic", "platform": "vertex", "project_id": "p", "region": "global"}
    )
    local = _llm(cfg_dir, {"kind": "openai_compat", "base_url": "http://localhost:11434/v1"})
    other = _llm(cfg_dir, {"kind": "openai_compat", "base_url": "https://llm.example/v1"})
    assert len({api, vertex, local, other}) == 4
    # Retry settings say how the call is made, not which model answers: no new gate run.
    tuned = {"kind": "anthropic", "platform": "api", "api_key_secret_name": "a", "max_attempts": 5}
    assert _llm(cfg_dir, tuned) == api


def test_a_refused_provider_needs_a_person(cfg_dir):
    rt, cfg = build(cfg_dir)

    def refused(*a, **k):
        raise ProviderError("anthropic: AuthenticationError 401")

    rt.llm.chat = refused
    run = rt.handle("test-agent", "svc:test-agent", (cfg.inputs_dir / "create.txt").read_bytes())
    assert (run.state, run.reason_code) == (RunState.NEEDS_PERSON, "provider_error")


class _Status(Exception):
    def __init__(self, status):
        super().__init__(status)
        self.status_code = status


def test_backoff_is_exponential_with_jitter_and_bounded():
    waits = []
    calls = iter([_Status(529), _Status(503), _Status(429), _Status(500)])

    def call():
        raise next(calls)

    with pytest.raises(ProviderExhausted):
        with_retry(call, label="t", max_attempts=4, sleep=waits.append)
    assert len(waits) == 3  # none after the last attempt
    assert all(0 <= w <= ceiling for w, ceiling in zip(waits, (0.5, 1.0, 2.0), strict=True))
    assert max(waits) <= MAX_DELAY_S


@pytest.mark.parametrize("exc", [TimeoutError(), ConnectionResetError(), _Status(502)])
def test_network_failures_and_5xx_are_retried(exc):
    seen = []

    def call():
        seen.append(1)
        if len(seen) == 1:
            raise exc
        return "ok"

    assert with_retry(call, label="t", max_attempts=2, sleep=lambda s: None) == "ok"


@pytest.mark.parametrize(
    "exc", [_Status(400), _Status(403), KeyError("bug"), ValueError("bad json")]
)
def test_anything_else_fails_at_once(exc):
    seen = []

    def call():
        seen.append(1)
        raise exc

    with pytest.raises(ProviderError) as err:
        with_retry(call, label="t", max_attempts=3, sleep=lambda s: None)
    assert not isinstance(err.value, ProviderExhausted) and len(seen) == 1
