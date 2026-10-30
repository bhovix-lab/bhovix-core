"""Amazon Bedrock through the Converse API (IAM role, no key). Ports WARDEN ``BedrockProvider`` (design 4.3).

The route's ``model_id`` is a model or inference-profile id (or its ARN). Converse forces one named tool only for
the Anthropic and Amazon families; any other family gets the ``output_schema`` in the system prompt and answers in
text, read back as the same forced tool call. Needs ``hadavin-sdk[aws]``.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from typing import Any

import boto3  # the extra: a missing install fails at start-up with the hint (backends.make)
from botocore.config import Config

from hadavin_sdk.llm.common import (
    ANSWER_TOOL,
    Answer,
    NetworkLLM,
    json_in_text,
    pinned,
    reply,
    schema_hint,
)
from hadavin_sdk.models import Reply, ToolCall

FORCED_TOOL_FAMILIES = frozenset({"anthropic", "amazon"})
# Inference-profile prefixes: a geography (or `global`) in front of the model id.
_GEO = frozenset({"global", "in", "apac", "us", "eu", "jp", "au", "ca", "us-gov"})


def family(model_id: str) -> str:
    """`anthropic` for `in.anthropic.<model>` (or its ARN), `openai` for `openai.<model>`."""
    parts = model_id.rsplit("/", 1)[-1].split(".")
    return parts[1] if len(parts) > 2 and parts[0] in _GEO else parts[0]


def make(settings: Any, deps: Any) -> BedrockLLM:
    client = boto3.client(
        "bedrock-runtime",
        region_name=settings.region,
        config=Config(
            read_timeout=settings.call_timeout_s,
            connect_timeout=min(10.0, settings.call_timeout_s),
            # One request per attempt: llm/retry.py decides. total_max_attempts counts the first request;
            # WARDEN's `max_attempts: 1` meant one retry.
            retries={"total_max_attempts": 1, "mode": "standard"},
            # AWS_ENDPOINT_URL(_BEDROCK_RUNTIME) would send the signed prompt to another host.
            ignore_configured_endpoint_urls=True,
        ),
    )
    return BedrockLLM(client, pinned(dict(deps.routes)), settings.max_attempts)


class BedrockLLM(NetworkLLM):
    label = "bedrock"

    def __init__(
        self,
        client: Any,
        routes: dict[str, Any],
        max_attempts: int,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        super().__init__(routes, max_attempts, sleep)
        self._client = client

    def _chat(self, route, system, turns, specs, forced, output_schema) -> Reply:
        in_text = forced is not None and family(route.model_id) not in FORCED_TOOL_FAMILIES
        if in_text:
            system, specs = schema_hint(system, output_schema), []
        request: dict[str, Any] = {
            "modelId": route.model_id,
            "messages": [
                {"role": role, "content": [{"text": t} for t in texts]} for role, texts in turns
            ],
            "inferenceConfig": {"maxTokens": route.max_tokens},
        }
        if system:  # Converse refuses a blank text block
            request["system"] = [{"text": system}]
        if specs:
            request["toolConfig"] = {
                "tools": [
                    {
                        "toolSpec": {
                            "name": s["name"],
                            "description": s["description"],
                            "inputSchema": {"json": s["input_schema"]},
                        }
                    }
                    for s in specs
                ],
                "toolChoice": {"tool": {"name": forced}} if forced else {"auto": {}},
            }
        started = time.monotonic()
        got = self._retry(lambda: self._parse(self._client.converse(**request), in_text))
        return reply(
            route, **vars(got), started=started, sent=system + json.dumps(request["messages"])
        )

    @staticmethod
    def _parse(resp: dict[str, Any], in_text: bool) -> Answer:
        content = resp["output"]["message"]["content"]
        text = "".join(c.get("text", "") for c in content)
        calls = [
            ToolCall(name=c["toolUse"]["name"], input=c["toolUse"]["input"])
            for c in content
            if "toolUse" in c
        ]
        if in_text and (found := json_in_text(text)) is not None:
            calls = [ToolCall(name=ANSWER_TOOL, input=found)]
        usage = resp.get("usage") or {}
        return Answer(
            text=text,
            calls=calls,
            tokens=(usage.get("inputTokens"), usage.get("outputTokens")),
            stop=resp.get("stopReason"),
        )
