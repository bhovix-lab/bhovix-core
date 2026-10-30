"""The network llm kinds (all slice2-unverified), each against hand-written fixtures: a local HTTP replay for
anthropic (three platforms), openai_compat and gemini; botocore's Stubber for bedrock (moto lacks Converse).

A wire harness: ``serve(*fixtures, routes=None) -> llm`` queues fixture responses and builds the kind;
``requests`` holds what was sent; ``max_tokens(body)`` and ``forced(body)`` read a sent request;
``answer(name, input)`` is a tool-call fixture for any call, ``cut_off()`` one stopped at the output cap;
``close()``.
"""

import copy
import json

import pytest

from tests.contracts.kinds import kind
from tests.contracts.kinds.builtin import ROUTES
from tests.fixtures.http_fake import Replay, fixture

KEY = "contract" + "-key"  # built from parts: never a real-looking key


class _HttpWire:
    kind_name = ""

    def __init__(self) -> None:
        self.replay = Replay()

    @property
    def requests(self) -> list[dict]:
        return [r["body"] for r in self.replay.requests]

    def scenario(self, name: str) -> dict:
        return fixture(self.kind_name, name)

    def serve(self, *fixtures, routes=None):
        self.replay.queue.extend(copy.deepcopy(fixtures))
        self.routes = routes or ROUTES
        return self.build(self.routes)

    def close(self) -> None:
        self.replay.close()


class AnthropicWire(_HttpWire):
    kind_name = "anthropic"

    def __init__(self, platform: str) -> None:
        super().__init__()
        self.platform = platform

    def build(self, routes):
        anthropic = pytest.importorskip("anthropic", reason="needs extra anthropic")

        from hadavin_sdk.llm.anthropic import AnthropicLLM

        common = {"base_url": self.replay.url, "max_retries": 0, "timeout": 5.0}
        if self.platform == "vertex":
            client = anthropic.AnthropicVertex(
                region="contract-region", project_id="contract-project", access_token=KEY, **common
            )
        elif self.platform == "foundry":
            common["base_url"] += "/anthropic/"
            client = anthropic.AnthropicFoundry(api_key=KEY, **common)
        else:
            client = anthropic.Anthropic(api_key=KEY, **common)
        return AnthropicLLM(client, routes, 3, sleep=lambda s: None)

    def max_tokens(self, body):
        return body["max_tokens"]

    def forced(self, body):
        return (body.get("tool_choice") or {}).get("name")

    def answer(self, name, args):
        fx = self.scenario("tool_call")
        fx["body"]["content"][0].update(name=name, input=args)
        return fx

    def cut_off(self):
        fx = self.scenario("tool_call")
        fx["body"]["stop_reason"] = "max_tokens"
        return fx


class OpenAICompatWire(_HttpWire):
    kind_name = "openai_compat"

    def build(self, routes):
        from hadavin_sdk.llm.openai_compat import OpenAICompatLLM

        return OpenAICompatLLM(
            self.replay.url + "/v1", lambda: KEY, routes, 5.0, 3, sleep=lambda s: None
        )

    def max_tokens(self, body):
        return body["max_tokens"]

    def forced(self, body):
        return ((body.get("tool_choice") or {}).get("function") or {}).get("name")

    def answer(self, name, args):
        fx = self.scenario("tool_call")
        fn = fx["body"]["choices"][0]["message"]["tool_calls"][0]["function"]
        fn.update(name=name, arguments=json.dumps(args))
        return fx

    def cut_off(self):
        fx = self.scenario("tool_call")
        fx["body"]["choices"][0]["finish_reason"] = "length"
        return fx


class GeminiWire(_HttpWire):
    kind_name = "gemini"

    def build(self, routes):
        from hadavin_sdk.llm import gemini

        llm = gemini.GeminiLLM(lambda: KEY, routes, 5.0, 3, sleep=lambda s: None)
        llm.base_url = self.replay.url  # the fixed host, pointed at the replay
        return llm

    def max_tokens(self, body):
        return body["generationConfig"]["maxOutputTokens"]

    def forced(self, body):
        names = (body.get("toolConfig") or {}).get("functionCallingConfig", {})
        return (names.get("allowedFunctionNames") or [None])[0]

    def answer(self, name, args):
        fx = self.scenario("tool_call")
        fx["body"]["candidates"][0]["content"]["parts"][0]["functionCall"] = {
            "name": name,
            "args": args,
        }
        return fx

    def cut_off(self):
        fx = self.scenario("tool_call")
        fx["body"]["candidates"][0]["finishReason"] = "MAX_TOKENS"
        return fx


class BedrockWire:
    """Converse through botocore's Stubber: it checks every request and fixture against the service model."""

    kind_name = "bedrock"

    def __init__(self, model_id: str = "") -> None:
        boto3 = pytest.importorskip("boto3", reason="needs extra aws")
        from botocore import UNSIGNED
        from botocore.config import Config
        from botocore.stub import Stubber

        self.model_id = model_id
        # Unsigned: no credential lookup, so a developer's own AWS profile is never touched.
        self.client = boto3.client(
            "bedrock-runtime",
            region_name="contract-region-1",
            config=Config(signature_version=UNSIGNED),
        )
        self.requests: list[dict] = []
        self.client.meta.events.register(
            "provide-client-params.bedrock-runtime.Converse",
            lambda params, **kw: self.requests.append(copy.deepcopy(params)),
        )
        self.stub = Stubber(self.client)
        self.stub.activate()

    def scenario(self, name):
        return fixture("bedrock", name)

    def serve(self, *fixtures, routes=None):
        from hadavin_sdk.llm.bedrock import BedrockLLM

        for fx in fixtures:
            if fx["status"] == 200:
                self.stub.add_response("converse", copy.deepcopy(fx["body"]))
            else:
                self.stub.add_client_error(
                    "converse",
                    service_error_code=fx["body"]["Error"]["Code"],
                    service_message=fx["body"]["Error"]["Message"],
                    http_status_code=fx["status"],
                )
        routes = routes or ROUTES
        if self.model_id:
            routes = {
                k: r.model_copy(update={"model_id": self.model_id}) for k, r in routes.items()
            }
        self.routes = routes
        return BedrockLLM(self.client, routes, 3, sleep=lambda s: None)

    def max_tokens(self, body):
        return body["inferenceConfig"]["maxTokens"]

    def forced(self, body):
        return ((body.get("toolConfig") or {}).get("toolChoice") or {}).get("tool", {}).get("name")

    def answer(self, name, args):
        fx = self.scenario("tool_call")
        fx["body"]["output"]["message"]["content"][0]["toolUse"].update(name=name, input=args)
        return fx

    def cut_off(self):
        fx = self.scenario("tool_call")
        fx["body"]["stopReason"] = "max_tokens"
        return fx

    def close(self):
        self.stub.deactivate()


for _platform in ("api", "vertex", "foundry"):
    kind("llm_wire", f"anthropic.{_platform}")(lambda tmp_path, p=_platform: AnthropicWire(p))
kind("llm_wire", "openai_compat")(lambda tmp_path: OpenAICompatWire())
kind("llm_wire", "gemini")(lambda tmp_path: GeminiWire())
# A forced-tool family: the suite's model id must name one (in.anthropic.<model>).
kind("llm_wire", "bedrock")(lambda tmp_path: BedrockWire("in.anthropic.contract-model"))
