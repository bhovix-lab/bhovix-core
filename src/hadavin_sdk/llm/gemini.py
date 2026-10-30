"""Google Gemini (AI Studio API key) over stdlib HTTP, no SDK. Ports WARDEN ``GeminiProvider`` (design 4.3).

The base URL is fixed here, never read from the environment: the Google SDK reads GOOGLE_GEMINI_BASE_URL and
the Vertex switches itself, and the key went wherever they named (WARDEN reviews, 2026-09-30). The key travels in
the ``x-goog-api-key`` header, never the URL, and is read on every call (a rotated key is picked up).
``output_schema`` is forced through function calling mode ``ANY``.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from typing import Any
from urllib.parse import quote

from hadavin_sdk.llm.common import Answer, NetworkLLM, pinned, post_json, reply
from hadavin_sdk.models import Reply, ToolCall

BASE_URL = "https://generativelanguage.googleapis.com/v1beta"


def make(settings: Any, deps: Any) -> GeminiLLM:
    return GeminiLLM(
        lambda: deps.resolve(settings.api_key_secret_name),
        pinned(dict(deps.routes)),
        settings.call_timeout_s,
        settings.max_attempts,
    )


class GeminiLLM(NetworkLLM):
    label = "gemini"

    def __init__(
        self,
        key: Callable[[], str],
        routes: dict[str, Any],
        call_timeout_s: float,
        max_attempts: int,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        super().__init__(routes, max_attempts, sleep)
        self._key, self.timeout_s, self.base_url = key, call_timeout_s, BASE_URL

    def _chat(self, route, system, turns, specs, forced, output_schema) -> Reply:
        body: dict[str, Any] = {
            "contents": [
                {
                    "role": "model" if role == "assistant" else "user",
                    "parts": [{"text": t} for t in texts],
                }
                for role, texts in turns
            ],
            "generationConfig": {"maxOutputTokens": route.max_tokens},
        }
        if system:
            body["systemInstruction"] = {"parts": [{"text": system}]}
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
        url = f"{self.base_url}/models/{quote(route.model_id, safe='')}:generateContent"
        started = time.monotonic()
        got = self._retry(
            lambda: self._parse(
                post_json(url, body, {"x-goog-api-key": self._key()}, self.timeout_s)
            )
        )
        return reply(
            route, **vars(got), started=started, sent=system + json.dumps(body["contents"])
        )

    @staticmethod
    def _parse(resp: dict[str, Any]) -> Answer:
        usage = resp.get("usageMetadata") or {}
        # Thinking is billed as output; candidatesTokenCount leaves it out.
        out = (usage.get("candidatesTokenCount") or 0) + (usage.get("thoughtsTokenCount") or 0)
        tokens = (usage.get("promptTokenCount"), out or None)
        if not resp.get("candidates"):
            if (resp.get("promptFeedback") or {}).get(
                "blockReason"
            ):  # the prompt itself was blocked
                return Answer(text="", calls=[], tokens=tokens, stop="SAFETY")
            raise ValueError("gemini answered with no candidates")  # a ProviderError, never a guess
        candidate = resp["candidates"][0]
        if (
            candidate.get("finishReason") == "MALFORMED_FUNCTION_CALL"
        ):  # the model failed, it did not decide
            raise ValueError("gemini answered with a malformed function call")
        parts = (candidate.get("content") or {}).get("parts") or []
        return Answer(
            # Thought parts are the model's working, never its answer.
            text="".join(p.get("text", "") for p in parts if not p.get("thought")),
            calls=[
                ToolCall(name=p["functionCall"]["name"], input=p["functionCall"].get("args") or {})
                for p in parts
                if "functionCall" in p
            ],
            tokens=tokens,
            stop=candidate.get("finishReason"),
        )
