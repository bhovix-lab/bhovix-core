"""Structured extraction: validate, one retry with the validator's errors, then a dead letter."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from decimal import Decimal

from pydantic import BaseModel, ValidationError

from hadavin_sdk.llm.protocol import LLM
from hadavin_sdk.models import DeadLetter, Reply

_ASK = "Extract the fields from the attached document. Answer with JSON matching the schema only."


@dataclass
class Valid:
    data: BaseModel
    replies: list[Reply] = field(default_factory=list)

    @property
    def cost_usd(self) -> Decimal:
        return sum((r.cost_usd for r in self.replies), Decimal(0))


def _parse(reply: Reply) -> object:
    if reply.tool_calls:
        return reply.tool_calls[0].input
    return json.loads(reply.text)


def extract(
    llm: LLM,
    document: bytes,
    schema: type[BaseModel],
    *,
    run_id: str,
    route: str,
    system: str = "",
) -> Valid | DeadLetter:
    messages = [{"role": "user", "content": _ASK}]
    replies: list[Reply] = []
    errors: list[str] = []
    for _attempt in range(2):
        reply = llm.chat(
            messages,
            system=system,
            route=route,
            documents=[document],
            output_schema=schema.model_json_schema(),
        )
        replies.append(reply)
        try:
            return Valid(schema.model_validate(_parse(reply)), replies)
        except (ValidationError, ValueError) as exc:  # JSONDecodeError is a ValueError
            errors.append(f"{exc.__class__.__name__}: {str(exc)[:300]}")
            messages = [
                *messages,
                {"role": "assistant", "content": reply.text or "(tool call)"},
                {"role": "user", "content": f"That failed validation: {errors[-1]}. Try again."},
            ]
    return DeadLetter(run_id=run_id, reason="extract_invalid", errors=errors)
