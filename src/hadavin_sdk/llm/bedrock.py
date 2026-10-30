"""Amazon Bedrock through the Converse API (IAM role, no key). Ports WARDEN ``BedrockProvider`` (design 4.3).

The route's ``model_id`` is a model or inference-profile id. Converse forces one named tool only for the
Anthropic and Amazon families; any other family gets the ``output_schema`` in the system prompt and answers in
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
    json_in_text,
    pinned,
    reply,
    schema_hint,
    tools_for,
    turns,
)
from hadavin_sdk.llm.retry import with_retry
from hadavin_sdk.models import Reply, ToolCall

FORCED_TOOL_FAMILIES = frozenset({"anthropic", "amazon"})
# Inference-profile prefixes: a geography (or `global`) in front of the model id.
_GEO = frozenset({"global", "in", "apac", "us", "eu", "jp", "au", "ca", "us-gov"})


def family(model_id: str) -> str:
    """`anthropic` for `in.anthropic.<model>`, `openai` for `openai.<model>`."""
    parts = model_id.split(".")
    return parts[1] if len(parts) > 2 and parts[0] in _GEO else parts[0]


def make(settings: Any, deps: Any) -> BedrockLLM:
    # One attempt and a bounded socket: llm/retry.py decides, not the SDK.
    client = boto3.client(
        "bedrock-runtime",
        region_name=settings.region,
        config=Config(
            read_timeout=settings.call_timeout_s,
            connect_timeout=min(10.0, settings.call_timeout_s),
            # total_max_attempts counts the first request; plain max_attempts would add one retry.
            retries={"total_max_attempts": 1, "mode": "standard"},
        ),
    )
    return BedrockLLM(client, pinned(dict(deps.routes)), settings.max_attempts)


class BedrockLLM:
    def __init__(
        self,
        client: Any,
        routes: dict[str, Any],
        max_attempts: int,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._client, self.routes = client, routes
        self.max_attempts, self._sleep = max_attempts, sleep

    def chat(
        self,
        messages: list[dict[str, Any]],
        *,
        system: str,
        route: str,
        tools: list[dict[str, Any]] | None = None,
        documents: list[bytes] | None = None,
        output_schema: dict[str, Any] | None = None,
    ) -> Reply:
        r = self.routes[route]
        specs, forced = tools_for(tools, output_schema)
        in_text = forced is not None and family(r.model_id) not in FORCED_TOOL_FAMILIES
        if in_text:
            system, specs = schema_hint(system, output_schema), []
        request: dict[str, Any] = {
            "modelId": r.model_id,
            "system": [{"text": system}],
            "messages": [
                {"role": role, "content": [{"text": t} for t in texts]}
                for role, texts in turns(messages, documents)
            ],
            "inferenceConfig": {"maxTokens": r.max_tokens},
        }
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
        resp = with_retry(
            lambda: self._client.converse(**request),
            label="bedrock",
            max_attempts=self.max_attempts,
            sleep=self._sleep,
        )
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
        return reply(
            r,
            text=text,
            calls=calls,
            tokens=(usage.get("inputTokens"), usage.get("outputTokens")),
            stop=resp.get("stopReason"),
            started=started,
            sent=system + json.dumps(request["messages"]),
        )
