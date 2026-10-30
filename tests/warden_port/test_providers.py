"""Ported from WARDEN tests/test_providers.py (main c78d7709): the cases that apply to the rewritten kinds.

Edits: WARDEN picks a provider and its key from environment variables; Hadavin reads both from config and the
platform resolver, so the env-driven cases became config cases. Dropped (no Hadavin counterpart): the provider
aliases and their resolve() leak (no aliases: one `base_url`), `test_model_is_overridable_by_env` (model ids live
in `routes`), and the google-genai / openai SDK env cases (`..._into_vertex`, `..._org_and_project_ids_...`):
gemini and openai_compat use stdlib HTTP, so no SDK reads the environment.
"""

import pytest

from hadavin_sdk.actions.secrets import FakeSecretProvider
from hadavin_sdk.backends import make
from hadavin_sdk.backends.table import (
    AnthropicSettings,
    GeminiSettings,
    OpenAICompatSettings,
)
from hadavin_sdk.config import parse_backends
from hadavin_sdk.errors import ConfigError
from hadavin_sdk.llm import ProviderError
from hadavin_sdk.llm.common import estimate_tokens
from tests.contracts.kinds.builtin import ROUTES
from tests.contracts.kinds.llm_wire import KEY, GeminiWire, OpenAICompatWire
from tests.contracts.test_llm import CALL

# --------------------------------------------------------------------- token estimation


def test_estimate_is_deliberately_pessimistic():
    """A budget fed an under-estimate fails to stop the thing it exists to stop."""
    text = "x" * 1200
    assert estimate_tokens(text) == 400
    assert estimate_tokens(text) > len(text) // 4


def test_estimate_never_returns_zero():
    assert estimate_tokens("") >= 1
    assert estimate_tokens("a") >= 1


# --------------------------------------------------------------------- resolution


def test_unknown_provider_lists_the_valid_options(tmp_path):
    with pytest.raises(ConfigError) as exc:
        parse_backends(
            {"llm": {"kind": "banana"}, "audit": {"kind": "local_dir", "dir": "a"}}, tmp_path
        )
    msg = str(exc.value)
    assert "banana" in msg
    for known in ("anthropic", "bedrock", "gemini", "openai_compat"):
        assert known in msg


def test_gemini_without_a_key_points_at_where_to_get_one(tmp_path):
    """Hadavin: the key is a platform secret named in config, so a gemini entry without one fails at start-up."""
    with pytest.raises(ConfigError, match="api_key_secret_name"):
        parse_backends({"llm": "gemini", "audit": {"kind": "local_dir", "dir": "a"}}, tmp_path)


def test_ollama_needs_no_real_key():
    """Local models are the answer for teams that cannot send data anywhere. A key must not block that."""
    settings = OpenAICompatSettings(kind="openai_compat", base_url="http://localhost:11434/v1")
    llm = make("llm", settings, routes=ROUTES)
    assert llm.url == "http://localhost:11434/v1/chat/completions"
    assert llm._headers() == {}


def test_openai_without_key_or_base_url_fails_clearly():
    with pytest.raises(ValueError, match="base_url"):
        OpenAICompatSettings(kind="openai_compat")


# --------------------------------------------------------------------- response mapping


def test_openai_adapter_maps_text_and_usage():
    wire = OpenAICompatWire()
    try:
        reply = wire.serve(wire.scenario("text")).chat(**CALL)
        assert (reply.text, reply.input_tokens, reply.output_tokens) == (
            "No action is needed.",
            300,
            7,
        )
    finally:
        wire.close()


def test_openai_adapter_estimates_when_the_provider_reports_no_usage():
    """Some OpenAI-compatible servers (Ollama among them) omit usage. Zeros would disarm the budget."""
    wire = OpenAICompatWire()
    try:
        fx = wire.scenario("text")
        del fx["body"]["usage"]
        reply = wire.serve(fx).chat(**CALL)
        assert reply.input_tokens > 0, "no usage reported and no estimate - budget would never fire"
        assert reply.output_tokens > 0 and reply.cost_usd > 0
    finally:
        wire.close()


# --------------------------------------------------------------------- keys go only where configured


@pytest.mark.parametrize(
    "url", ["http://llm.internal.example/v1", "http://localhost:11434/v1", "ftp://x.example/"]
)
def test_the_openai_key_never_goes_to_another_vendor(url):
    """Audit A-C-18 (keys sent to the wrong host). Hadavin: a key only over https, to the configured host."""
    with pytest.raises(ValueError, match="https"):
        OpenAICompatSettings(kind="openai_compat", base_url=url, api_key_secret_name="k")  # noqa: S106 - a name


def test_a_custom_host_uses_its_own_key_variable():
    """Hadavin: the key comes from the entry's own platform secret, as a bearer header to its base_url."""
    settings = OpenAICompatSettings(
        kind="openai_compat",
        base_url="https://llm.internal.example/v1",
        api_key_secret_name="k",  # noqa: S106 - a name
    )
    llm = make("llm", settings, FakeSecretProvider({"k": KEY}), routes=ROUTES)
    assert llm._headers() == {"Authorization": f"Bearer {KEY}"}


def test_a_redirect_never_carries_the_key():
    wire = OpenAICompatWire()
    try:
        moved = {
            "request_match": {"method": "POST"},
            "status": 302,
            "headers": {"Location": wire.replay.url + "/stolen/chat/completions"},
            "body": {},
        }
        with pytest.raises(ProviderError):
            wire.serve(moved, wire.scenario("text")).chat(**CALL)
        assert [r["path"] for r in wire.replay.requests] == ["/v1/chat/completions"]
    finally:
        wire.close()


def test_the_gemini_key_goes_only_to_google(monkeypatch):
    """Second review (2026-09-30): the Google SDK read GOOGLE_GEMINI_BASE_URL, so the key went to whatever host it
    named. Hadavin uses no SDK: the host is fixed, and the key travels in a header, never the URL."""
    monkeypatch.setenv("GOOGLE_GEMINI_BASE_URL", "http://evil.example/")
    settings = GeminiSettings(kind="gemini", api_key_secret_name="g")  # noqa: S106 - a name
    llm = make("llm", settings, FakeSecretProvider({"g": KEY}), routes=ROUTES)
    assert llm.base_url == "https://generativelanguage.googleapis.com/v1beta"
    wire = GeminiWire()
    try:
        wire.serve(wire.scenario("text")).chat(**CALL)
        sent = wire.replay.requests[0]
        assert sent["headers"]["x-goog-api-key"] == KEY and KEY not in sent["path"]
    finally:
        wire.close()


@pytest.mark.parametrize(
    "env, platform, extra",
    [
        ("ANTHROPIC_BASE_URL", "api", {"api_key_secret_name": "a"}),
        ("ANTHROPIC_VERTEX_BASE_URL", "vertex", {"project_id": "p-1", "region": "global"}),
        ("ANTHROPIC_FOUNDRY_BASE_URL", "foundry", {"api_key_secret_name": "a", "resource": "acme"}),
    ],
)
def test_the_anthropic_key_goes_only_to_its_platform(monkeypatch, env, platform, extra):
    """WARDEN AnthropicProvider: an explicit base URL, or the SDK reads one from the environment."""
    pytest.importorskip("anthropic", reason="needs extra anthropic")
    monkeypatch.setenv(env, "http://evil.example/")
    settings = AnthropicSettings(kind="anthropic", platform=platform, **extra)
    llm = make("llm", settings, FakeSecretProvider({"a": KEY}), routes=ROUTES)
    host = str(llm._client.base_url)
    assert "evil" not in host and host.startswith("https://")
    assert llm._client.max_retries == 0


@pytest.mark.parametrize(
    "platform, extra, missing",
    [
        ("api", {}, "api_key_secret_name"),
        ("vertex", {"region": "global"}, "project_id"),
        ("foundry", {"api_key_secret_name": "a"}, "resource"),
        ("foundry", {"api_key_secret_name": "a", "resource": "evil.example/x"}, "resource"),
    ],
)
def test_each_anthropic_platform_names_what_it_needs(platform, extra, missing):
    with pytest.raises(ValueError, match=missing):
        AnthropicSettings(kind="anthropic", platform=platform, **extra)


@pytest.mark.parametrize("model", ["sonnet", "opus[1m]", "claude-x-latest", "llama3:latest", " "])
def test_a_model_must_be_named_exactly(model):
    """Register M15: an alias moves to new models, so a qualified agent would silently change model."""
    routes = {"default": ROUTES["default"].model_copy(update={"model_id": model})}
    settings = OpenAICompatSettings(kind="openai_compat", base_url="http://localhost:11434/v1")
    with pytest.raises(ConfigError, match="exact model id"):
        make("llm", settings, routes=routes)
