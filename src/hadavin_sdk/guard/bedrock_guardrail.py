"""``bedrock_guardrail``: Amazon Bedrock Guardrails' prompt-attack filter (design 4.3). Needs ``hadavin-sdk[aws]``.

``ApplyGuardrail`` with ``source=INPUT`` on the text alone (no model call). The score is 1.0 when the guardrail's
PROMPT_ATTACK filter blocked or detected the text, else 0.0; its other policies (topics, words, PII) are not an
injection signal here. Any API error, an answer that is not one of the documented shapes, or text the guardrail
only partly screened raises, which ``injection_check`` turns into a flag (fail closed).

Known limit: a guardrail whose PROMPT_ATTACK input filter is missing or set to NONE never flags. Its
configuration is the client's (S11 checklist); the P9 live run screens the seeded injection once.
"""

from __future__ import annotations

from typing import Any

import boto3  # the extra: a missing install fails at start-up with the hint (backends.make)
from botocore.config import Config

from hadavin_sdk.models import Verdict

_ACTIONS = frozenset({"NONE", "GUARDRAIL_INTERVENED"})


def make(settings: Any, deps: Any) -> GuardrailDetector:
    client = boto3.client(
        "bedrock-runtime",
        region_name=settings.region,
        config=Config(
            connect_timeout=5,
            read_timeout=10,
            # total_max_attempts counts the first request: one retry for a blip, then the run is flagged.
            retries={"total_max_attempts": 2, "mode": "standard"},
            # AWS_ENDPOINT_URL(_BEDROCK_RUNTIME) would send the screened text to another host.
            ignore_configured_endpoint_urls=True,
        ),
    )
    return GuardrailDetector(
        client, settings.guardrail_id, settings.guardrail_version, settings.threshold
    )


def _prompt_attack(resp: dict[str, Any]) -> bool:
    if resp.get("action") not in _ACTIONS or not isinstance(resp.get("assessments"), list):
        raise ValueError("guardrail answer not in the documented shape")
    chars = (resp.get("guardrailCoverage") or {}).get("textCharacters") or {}
    if chars and chars.get("guarded", 0) < chars.get("total", 0):
        raise ValueError("guardrail screened only part of the text")
    for assessment in resp["assessments"]:
        for f in (assessment.get("contentPolicy") or {}).get("filters") or []:
            if f.get("type") == "PROMPT_ATTACK" and (
                f.get("detected") or f.get("action") == "BLOCKED"
            ):
                return True
    return False


class GuardrailDetector:
    backend = "bedrock_guardrail"

    def __init__(self, client: Any, guardrail_id: str, version: str, threshold: float) -> None:
        self._client, self.guardrail_id, self.version = client, guardrail_id, version
        self.threshold = threshold

    def check(self, text: str, source: str) -> Verdict:
        if not text.strip():  # nothing to screen; the API refuses empty content
            return Verdict(flagged=False, score=0.0, backend=self.backend)
        resp = self._client.apply_guardrail(
            guardrailIdentifier=self.guardrail_id,
            guardrailVersion=self.version,
            source="INPUT",
            content=[{"text": {"text": text}}],
        )
        score = 1.0 if _prompt_attack(resp) else 0.0
        flagged = score >= self.threshold
        return Verdict(
            flagged=flagged,
            score=score,
            backend=self.backend,
            reason_code="injection_suspected" if flagged else None,
        )
