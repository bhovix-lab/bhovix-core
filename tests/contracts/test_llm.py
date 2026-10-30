"""LLM suite over every network kind (design §6, §12.6 P5): anthropic × 3 platforms, bedrock, openai_compat,
gemini, each on hand-written fixtures. `fake` meets the reply check in test_capabilities.py; it has no network,
so the throttle and request-shape checks do not apply to it."""

import json
from decimal import Decimal

import pytest

from hadavin_sdk import evals
from hadavin_sdk.config import load_config
from hadavin_sdk.llm import ProviderError, ProviderExhausted
from hadavin_sdk.llm.common import ANSWER_TOOL
from hadavin_sdk.models import ToolCall
from hadavin_sdk.registry import load_registry
from tests.contracts.kinds.builtin import ROUTES

CALL = {
    "messages": [{"role": "user", "content": "Process the attached request document."}],
    "system": "Be exact.",
    "route": "default",
}
TOOLS = [
    {
        "name": "create_draft_record",
        "description": "Create a draft record.",
        "input_schema": {"type": "object", "properties": {"amount": {"type": "string"}}},
    },
    {"name": "echo"},  # a hook tool: name only
]
SCHEMA = {
    "type": "object",
    "properties": {"total": {"type": "string"}},
    "required": ["total"],
}


def _cost(tokens_in, tokens_out):
    r = ROUTES["default"]
    return (
        Decimal(tokens_in) * r.input_usd_per_mtok + Decimal(tokens_out) * r.output_usd_per_mtok
    ) / Decimal(1_000_000)


def test_a_tool_call_becomes_a_toolcall_priced_from_the_route(wire):
    llm = wire.serve(wire.scenario("tool_call"))
    reply = llm.chat(**CALL, tools=TOOLS, documents=[b"Standing desk, 249.00"])
    assert reply.tool_calls == [
        ToolCall(name="create_draft_record", input={"amount": "249.00", "title": "Standing desk"})
    ]
    assert (reply.input_tokens, reply.output_tokens) == (1200, 40)
    assert reply.cost_usd == _cost(1200, 40)
    assert reply.model_id == wire.routes["default"].model_id
    sent = wire.requests[-1]
    assert wire.max_tokens(sent) == ROUTES["default"].max_tokens
    assert wire.forced(sent) is None
    assert "Standing desk, 249.00" in json.dumps(sent)  # the document goes as text


def test_output_schema_is_a_forced_tool_call(wire):
    llm = wire.serve(wire.answer(ANSWER_TOOL, {"total": "249.00"}))
    reply = llm.chat(**CALL, output_schema=SCHEMA)
    assert wire.forced(wire.requests[-1]) == ANSWER_TOOL
    assert reply.tool_calls == [ToolCall(name=ANSWER_TOOL, input={"total": "249.00"})]


def test_a_text_answer_reports_text_tokens_and_model(wire):
    reply = wire.serve(wire.scenario("text")).chat(**CALL)
    assert reply.text == "No action is needed." and reply.tool_calls == []
    assert reply.cost_usd == _cost(300, 7)


def test_three_throttles_exhaust_after_exactly_max_attempts(wire):
    throttle = wire.scenario("throttle")
    llm = wire.serve(throttle, throttle, throttle, wire.scenario("text"))
    with pytest.raises(ProviderExhausted):
        llm.chat(**CALL)
    assert len(wire.requests) == 3  # max_attempts, and the 4th fixture is never asked for


def test_a_throttle_then_an_answer_succeeds(wire):
    reply = wire.serve(wire.scenario("throttle"), wire.scenario("text")).chat(**CALL)
    assert reply.text == "No action is needed." and len(wire.requests) == 2


def test_a_cut_off_answer_is_charged_and_its_tool_call_dropped(wire):
    """An answer stopped at the output cap may hold an incomplete tool input: never acted on (WARDEN M7)."""
    reply = wire.serve(wire.cut_off()).chat(**CALL, tools=TOOLS)
    assert reply.stop_reason == "max_tokens" and reply.tool_calls == []
    assert reply.cost_usd == _cost(1200, 40)


def test_a_malformed_answer_is_a_provider_error(wire):
    if wire.kind_name == "bedrock":
        pytest.skip("Stubber refuses a malformed Converse shape before the kind sees it")
    bad = {"request_match": {"method": "POST"}, "status": 200, "headers": {}, "body": {"error": {}}}
    with pytest.raises(ProviderError) as err:
        wire.serve(bad).chat(**CALL)
    assert not isinstance(err.value, ProviderExhausted) and len(wire.requests) == 1


def test_a_refused_key_fails_at_once_and_is_not_exhaustion(wire):
    llm = wire.serve(wire.scenario("denied"), wire.scenario("text"))
    with pytest.raises(ProviderError) as err:
        llm.chat(**CALL)
    assert not isinstance(err.value, ProviderExhausted)
    assert len(wire.requests) == 1


def test_the_evals_gate_is_green_on_the_kinds_fixtures(wire, cfg_dir):
    cfg = load_config(cfg_dir)
    reg = load_registry(cfg)
    golden = (cfg.golden_dir / "test-agent.jsonl").read_text(encoding="utf-8").splitlines()
    answers = [
        wire.answer(c["expected"]["action"], c["expected"]["inputs"])
        for c in map(json.loads, filter(None, golden))
    ]
    run = evals.gate(reg, wire.serve(*answers, routes=cfg.routes), "test-agent")
    assert run.green and run.n == len(answers) == len(wire.requests)
