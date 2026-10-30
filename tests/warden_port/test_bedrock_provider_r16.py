"""Ported from WARDEN tests/test_bedrock_provider_r16.py (main c78d7709), on botocore's Stubber instead of a
hand-rolled stub, so every request and fixture is checked against the Converse service model.

Edits: model ids are test ids, never real ones. Dropped `test_a_whole_incident_runs_through_bedrock...` (WARDEN's
incident graph; the evals gate over the kinds' fixtures is in tests/contracts/test_llm.py). The qualification half
of `test_a_model_must_be_named_exactly_and_pass_qualification` is dropped (design §8: core qualifies through
`evals`); the exact-id half stays.
"""

import json

import pytest

from hadavin_sdk.backends import make
from hadavin_sdk.backends.table import BedrockSettings
from hadavin_sdk.errors import ConfigError
from hadavin_sdk.llm import ProviderError, ProviderExhausted
from hadavin_sdk.llm.bedrock import family
from hadavin_sdk.llm.common import ANSWER_TOOL
from tests.contracts.kinds.builtin import ROUTES
from tests.contracts.kinds.llm_wire import BedrockWire
from tests.contracts.test_llm import CALL, SCHEMA

boto3 = pytest.importorskip("boto3", reason="needs extra aws")
PROFILE = "in.anthropic.contract-model"
ANSWER = {"total": "249.00"}


@pytest.fixture(autouse=True)
def _no_aws_identity(monkeypatch, tmp_path):
    """boto3 looks for credentials when a client is built: never a developer's own profile, never IMDS."""
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "none"))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(tmp_path / "none"))
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    monkeypatch.setattr(boto3, "DEFAULT_SESSION", None)  # a cached session keeps its old profile


@pytest.fixture
def wire():
    w = BedrockWire(PROFILE)
    yield w
    w.close()


def test_the_answer_is_forced_through_one_tool_whose_schema_is_the_answer_schema(wire):
    out = wire.serve(wire.answer(ANSWER_TOOL, ANSWER)).chat(**CALL, output_schema=SCHEMA)
    req = wire.requests[0]
    assert req["modelId"] == PROFILE
    assert req["system"] == [{"text": CALL["system"]}]
    assert req["messages"] == [
        {"role": "user", "content": [{"text": CALL["messages"][0]["content"]}]}
    ]
    tool = req["toolConfig"]["tools"][0]["toolSpec"]
    assert req["toolConfig"]["toolChoice"] == {"tool": {"name": tool["name"]}}
    assert tool["inputSchema"]["json"] == SCHEMA
    assert out.tool_calls[0].input == ANSWER
    assert (out.input_tokens, out.output_tokens) == (1200, 40)


def test_throttling_waits_and_other_errors_are_failures(wire):
    throttle = wire.scenario("throttle")
    with pytest.raises(ProviderExhausted):
        wire.serve(throttle, throttle, throttle).chat(**CALL)
    with pytest.raises(ProviderError) as denied:
        wire.serve(wire.scenario("denied")).chat(**CALL)
    assert not isinstance(denied.value, ProviderExhausted)
    assert "AccessDeniedException" in str(denied.value)


def test_a_model_must_be_named_exactly():
    routes = {"default": ROUTES["default"].model_copy(update={"model_id": "sonnet"})}
    with pytest.raises(ConfigError, match="alias"):
        make("llm", BedrockSettings(kind="bedrock", region="contract-region-1"), routes=routes)


def test_the_client_never_retries_and_has_a_bounded_socket():
    settings = BedrockSettings(kind="bedrock", region="contract-region-1", call_timeout_s=7)
    client = make("llm", settings, routes=ROUTES)._client
    assert client.meta.region_name == "contract-region-1"
    assert client.meta.config.retries["total_max_attempts"] == 1  # WARDEN's max_attempts=1 meant 2
    assert client.meta.config.read_timeout == 7


def test_the_endpoint_never_comes_from_the_environment(monkeypatch):
    """Hadavin: AWS_ENDPOINT_URL would send the signed prompt elsewhere (the base-URL lesson of WARDEN's reviews)."""
    monkeypatch.setenv("AWS_ENDPOINT_URL", "http://evil.example")
    monkeypatch.setenv("AWS_ENDPOINT_URL_BEDROCK_RUNTIME", "http://evil.example")
    settings = BedrockSettings(kind="bedrock", region="contract-region-1")
    client = make("llm", settings, routes=ROUTES)._client
    assert client.meta.endpoint_url == "https://bedrock-runtime.contract-region-1.amazonaws.com"


@pytest.mark.parametrize(
    ("model", "fam"),
    [
        ("arn:aws:bedrock:r:0:inference-profile/in.anthropic.contract-model", "anthropic"),
        ("in.anthropic.contract-model", "anthropic"),
        ("global.anthropic.contract-model", "anthropic"),
        ("anthropic.contract-model", "anthropic"),
        ("openai.contract-model", "openai"),
        ("global.xai.contract-model", "xai"),
        ("apac.amazon.contract-model-v1:0", "amazon"),
        ("us.meta.contract-model-v1:0", "meta"),
    ],
)
def test_the_family_is_read_through_any_geography_prefix(model, fam):
    assert family(model) == fam


def test_a_family_converse_cannot_force_answers_in_text_and_is_still_typed():
    wire = BedrockWire("global.openai.contract-model")
    try:
        fx = wire.scenario("text")
        fx["body"]["output"]["message"]["content"] = [
            {"reasoningContent": {"reasoningText": {"text": "thinking"}}},
            {"text": "Here it is: " + json.dumps(ANSWER)},
        ]
        out = wire.serve(fx).chat(**CALL, output_schema=SCHEMA)
        req = wire.requests[0]
        assert "toolConfig" not in req
        assert json.dumps(SCHEMA, sort_keys=True) in req["system"][0]["text"]
        assert out.tool_calls[0].name == ANSWER_TOOL and out.tool_calls[0].input == ANSWER
    finally:
        wire.close()
