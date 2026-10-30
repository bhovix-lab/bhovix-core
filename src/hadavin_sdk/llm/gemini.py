"""Google Gemini (AI Studio API key) over stdlib HTTP, no SDK. Ports WARDEN ``GeminiProvider`` (design 4.3).

The base URL is fixed here, never read from the environment: the Google SDK reads GOOGLE_GEMINI_BASE_URL and
the Vertex switches itself, and the key went wherever they named (WARDEN reviews, 2026-09-30). The key travels in
the ``x-goog-api-key`` header, never the URL. ``output_schema`` is forced through function calling mode ``ANY``.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from typing import Any
from urllib.parse import quote

from hadavin_sdk.llm.common import pinned, post_json, reply, tools_for, turns
from hadavin_sdk.llm.retry import with_retry
from hadavin_sdk.models import Reply, ToolCall

BASE_URL = "https://generativelanguage.googleapis.com/v1beta"


def make(settings: Any, deps: Any) -> GeminiLLM:
    return GeminiLLM(
        deps.resolve(settings.api_key_secret_name),
        pinned(dict(deps.routes)),
        settings.call_timeout_s,
        settings.max_attempts,
    )


class GeminiLLM:
    def __init__(
        self,
        api_key: str,
        routes: dict[str, Any],
        call_timeout_s: float,
        max_attempts: int,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._headers = {"x-goog-api-key": api_key}
        self.base_url = BASE_URL
        self.routes, self.timeout_s = routes, call_timeout_s
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
        body: dict[str, Any] = {
            "systemInstruction": {"parts": [{"text": system}]},
            "contents": [
                {
                    "role": "model" if role == "assistant" else "user",
                    "parts": [{"text": t} for t in texts],
                }
                for role, texts in turns(messages, documents)
            ],
            "generationConfig": {"maxOutputTokens": r.max_tokens},
        }
        if specs:
            body["tools"] = [
                {
                    "functionDeclarations": [
                        {
                            "name": s["name"],
                            "description": s["description"],
                            "parametersJsonSchema": s["input_schema"],
                        }
                        for s in specs
                    ]
                }
            ]
        if forced:
            body["toolConfig"] = {
                "functionCallingConfig": {"mode": "ANY", "allowedFunctionNames": [forced]}
            }
        url = f"{self.base_url}/models/{quote(r.model_id, safe='')}:generateContent"
        started = time.monotonic()
        resp = with_retry(
            lambda: post_json(url, body, self._headers, self.timeout_s),
            label="gemini",
            max_attempts=self.max_attempts,
            sleep=self._sleep,
        )
        candidate = (resp.get("candidates") or [{}])[0]
        parts = (candidate.get("content") or {}).get("parts") or []
        usage = resp.get("usageMetadata") or {}
        return reply(
            r,
            # Thought parts are the model's working, never its answer.
            text="".join(p.get("text", "") for p in parts if not p.get("thought")),
            calls=[
                ToolCall(name=p["functionCall"]["name"], input=p["functionCall"].get("args") or {})
                for p in parts
                if "functionCall" in p
            ],
            tokens=(usage.get("promptTokenCount"), usage.get("candidatesTokenCount")),
            stop=candidate.get("finishReason"),
            started=started,
            sent=system + json.dumps(body["contents"]),
        )
