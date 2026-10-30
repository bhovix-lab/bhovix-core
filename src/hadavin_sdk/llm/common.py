"""What every network llm kind shares: tool and document shaping, the reply and its cost, a stdlib JSON POST.

Rewritten from WARDEN ``providers.py`` (single-turn ``complete`` → multi-turn ``chat`` with tools and documents).
"""

from __future__ import annotations

import json
import re
import time
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from decimal import Decimal
from typing import Any

from hadavin_sdk.errors import ConfigError
from hadavin_sdk.llm.retry import with_retry
from hadavin_sdk.models import Reply, ToolCall

# The forced tool an `output_schema` becomes: its input schema IS the schema, so the API enforces the shape.
ANSWER_TOOL = "submit_answer"
_EMPTY = {"type": "object", "properties": {}}

# WARDEN register M15: an alias moves when the vendor ships a new model, so a qualified agent would silently
# change model. Only exact ids are accepted.
# ponytail: a name heuristic; an untagged Ollama name (`llama3` = `llama3:latest`) still passes. Pin by digest
# when a client runs Ollama in production.
_FLOATING = re.compile(
    r"(?i)^(?:sonnet|opus|haiku|fable|default|best|opusplan)(?:\[1m\])?$|[-:]latest$"
)


def pinned(routes: dict[str, Any]) -> dict[str, Any]:
    """The routes, if every model id names one model; an alias that can move is refused."""
    for name, route in routes.items():
        if not route.model_id.strip() or _FLOATING.search(route.model_id.strip()):
            raise ConfigError(
                f"route {name}: model_id {route.model_id!r} is an alias that moves to new models; "
                "name an exact model id"
            )
    return routes


def estimate_tokens(text: str) -> int:
    """For a provider that reports no usage. Deliberately pessimistic (3 chars a token, never 0): a budget fed
    zeros never fires."""
    return max(1, len(text) // 3)


def tools_for(
    tools: list[dict[str, Any]] | None, output_schema: dict[str, Any] | None
) -> tuple[list[dict[str, Any]], str | None]:
    """``(tools as {name, description, input_schema}, the forced tool's name or None)``."""
    if output_schema is not None:
        answer = {
            "name": ANSWER_TOOL,
            "description": "Return the answer in this exact shape.",
            "input_schema": output_schema,
        }
        return [answer], ANSWER_TOOL
    return [
        {
            "name": t["name"],
            "description": t.get("description") or t["name"],
            "input_schema": t.get("input_schema") or _EMPTY,
        }
        for t in tools or []
    ], None


def turns(
    messages: list[dict[str, Any]], documents: list[bytes] | None
) -> list[tuple[str, list[str]]]:
    """``[(role, [text, ...])]``. Documents go first in the first user turn, as text (UTF-8, bad bytes
    replaced; PDF and image blocks are a trigger row)."""
    docs = [
        t for d in documents or [] if (t := d.decode("utf-8", "replace")).strip()
    ]  # APIs refuse blanks
    out: list[tuple[str, list[str]]] = []
    for m in messages:
        texts = [str(m["content"])]
        if docs and m["role"] == "user":
            texts, docs = docs + texts, []
        out.append((m["role"], texts))
    return out


def schema_hint(system: str, output_schema: dict[str, Any]) -> str:
    """For a model the API cannot force to a tool: the schema goes in the system prompt instead."""
    return (
        f"{system}\n\nAnswer with one JSON object matching this JSON schema, and nothing else:\n"
        f"{json.dumps(output_schema, sort_keys=True)}"
    )


def json_in_text(text: str) -> dict[str, Any] | None:
    """The first JSON object in a text answer (bare, fenced or after a sentence), or None."""
    start = text.find("{")
    while start != -1:
        try:
            found, _ = json.JSONDecoder().raw_decode(text, start)
        except ValueError:
            start = text.find("{", start + 1)
            continue
        return found if isinstance(found, dict) else None
    return None


# Why an answer ended, in each provider's words, folded into Reply.stop_reason (WARDEN providers.py B11, M7):
# `max_tokens` (cut off: incomplete, and asking again ends the same way) and `refusal` (declined or blocked).
_CUT_OFF = frozenset({"max_tokens", "model_context_window_exceeded", "length", "MAX_TOKENS"})
_REFUSED = frozenset(
    {
        "refusal",
        "content_filter",
        "content_filtered",
        "guardrail_intervened",
        "SAFETY",
        "RECITATION",
        "BLOCKLIST",
        "PROHIBITED_CONTENT",
        "SPII",
        "IMAGE_SAFETY",
    }
)


def stop_reason(raw: str | None, calls: list[ToolCall]) -> str:
    """``max_tokens`` | ``refusal`` | ``tool_use`` | ``end_turn``."""
    if raw in _CUT_OFF:
        return "max_tokens"
    if raw in _REFUSED:
        return "refusal"
    return "tool_use" if calls else "end_turn"


def reply(
    route: Any,
    *,
    text: str,
    calls: list[ToolCall],
    tokens: tuple[int | None, int | None],
    stop: str | None,
    started: float,
    sent: str,
) -> Reply:
    """The Reply, priced from the route. Missing usage is estimated from what was sent and received. A cut-off
    answer keeps its cost but loses its tool calls: their input may be incomplete."""
    tokens_in = tokens[0] or estimate_tokens(sent)
    tokens_out = tokens[1] or estimate_tokens(text + json.dumps([c.input for c in calls]))
    cost = (
        Decimal(tokens_in) * route.input_usd_per_mtok
        + Decimal(tokens_out) * route.output_usd_per_mtok
    ) / Decimal(1_000_000)
    stop = stop_reason(stop, calls)
    return Reply(
        text=text,
        tool_calls=[] if stop == "max_tokens" else calls,
        input_tokens=tokens_in,
        output_tokens=tokens_out,
        cost_usd=cost,
        model_id=route.model_id,
        stop_reason=stop,
        latency_ms=int((time.monotonic() - started) * 1000),
    )


@dataclass
class Answer:
    """One parsed provider answer, before pricing."""

    text: str
    calls: list[ToolCall]
    tokens: tuple[int | None, int | None]
    stop: str | None


class NetworkLLM:
    """The ``chat`` every network kind shares: the route, the tool list and bounded retries around one request
    and the parse of its answer, so a malformed answer is a ``ProviderError``, never a stray KeyError that
    would strand the run. A kind writes ``_chat``."""

    label = ""

    def __init__(
        self,
        routes: dict[str, Any],
        max_attempts: int,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.routes, self.max_attempts, self._sleep = routes, max_attempts, sleep

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
        return self._chat(r, system, turns(messages, documents), specs, forced, output_schema)

    def _chat(
        self,
        route: Any,
        system: str,
        turns: list[tuple[str, list[str]]],
        specs: list[dict[str, Any]],
        forced: str | None,
        output_schema: dict[str, Any] | None,
    ) -> Reply:
        raise NotImplementedError

    def _retry(self, call: Callable[[], Answer]) -> Answer:
        return with_retry(call, label=self.label, max_attempts=self.max_attempts, sleep=self._sleep)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect would carry the API key to a host nobody configured: refuse every redirect."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def post_json(url: str, body: dict[str, Any], headers: dict[str, str], timeout_s: float) -> Any:
    """One POST; an HTTP error status raises ``urllib.error.HTTPError`` (its ``code`` drives the retry)."""
    req = urllib.request.Request(  # noqa: S310 - https or keyless loopback, checked in the settings
        url,
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json", **headers},
        method="POST",
    )
    with _OPENER.open(req, timeout=timeout_s) as resp:  # nosec B310
        return json.loads(resp.read())
