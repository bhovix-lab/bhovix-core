"""Model adapter Protocol. Kinds: ``fake``, ``anthropic``, ``bedrock``, ``openai_compat``, ``gemini``."""

from __future__ import annotations

from typing import Any, Protocol

from hadavin_sdk.models import Reply


class ProviderError(RuntimeError):
    """The provider refused the request (a bad key, a malformed request): retrying would fail the same way."""


class ProviderExhausted(ProviderError):
    """The provider throttled or failed after its retries."""


class LLM(Protocol):
    def chat(
        self,
        messages: list[dict[str, Any]],
        *,
        system: str,
        route: str,
        tools: list[dict[str, Any]] | None = None,
        documents: list[bytes] | None = None,
        output_schema: dict[str, Any] | None = None,
    ) -> Reply: ...
