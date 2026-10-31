"""``llm_judge``: a model screens untrusted text for injection (design 4.3, 12.1; kept by the owner).

The only cloud-agnostic model detector: it runs on any configured llm route and kind (Claude, Bedrock, Gemini,
or a local open-weights model on `openai_compat`), so regex + llm_judge is a production detector set with no
single vendor. Minimal on purpose: one fixed, versioned
prompt (``judge_prompt.md``, its hash is in ``config_hash``), a forced JSON verdict, metered (the cost rides on the
Verdict and the caller charges it), qualified by its own golden set (``golden_dir/judge.jsonl``, run by the evals
gate). A tripwire OR-ed with at least one other detector (config refuses a judge alone), never the default: the
judge reads attacker text, so it can itself be steered, and a "clean" from it never clears anything.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from hadavin_sdk.guard.injection import injection_check
from hadavin_sdk.llm.common import ANSWER_TOOL
from hadavin_sdk.models import Verdict

PROMPT = (Path(__file__).parent / "judge_prompt.md").read_text(encoding="utf-8")
PROMPT_SHA256 = hashlib.sha256(PROMPT.encode("utf-8")).hexdigest()
SCHEMA = {
    "type": "object",
    "properties": {
        "injection": {"type": "boolean"},
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
    },
    "required": ["injection", "confidence"],
}
_ASK = "Screen the attached text (source: {source})."


def make(settings: Any, deps: Any) -> JudgeDetector:
    return JudgeDetector(deps.llm, settings.route, settings.threshold)


def _answer(reply: Any) -> tuple[bool, float] | None:
    """``(injection, confidence)`` exactly as the schema says, else None."""
    if reply.tool_calls:
        call = reply.tool_calls[0]
        answer = call.input if call.name == ANSWER_TOOL else None
    else:
        try:
            answer = json.loads(reply.text)
        except ValueError:
            return None
    if not isinstance(answer, dict):
        return None
    injection, confidence = answer.get("injection"), answer.get("confidence")
    numeric = isinstance(confidence, int | float) and not isinstance(confidence, bool)
    if not isinstance(injection, bool) or not numeric or not 0 <= confidence <= 1:
        return None
    return injection, float(confidence)


class JudgeDetector:
    backend = "llm_judge"

    def __init__(self, llm: Any, route: str, threshold: float) -> None:
        self.llm, self.route, self.threshold = llm, route, threshold

    def check(self, text: str, source: str) -> Verdict:
        reply = self.llm.chat(
            [{"role": "user", "content": _ASK.format(source=source)}],
            system=PROMPT,
            route=self.route,
            documents=[text.encode("utf-8")],
            output_schema=SCHEMA,
        )
        answer = _answer(reply)
        if answer is None:  # off schema (perhaps steered): a flag, and the call is still charged
            return Verdict(
                flagged=True,
                score=1.0,
                backend=self.backend,
                reason_code="guard_unavailable",
                cost_usd=reply.cost_usd,
            )
        injection, confidence = answer
        score = float(confidence) if injection else 0.0
        flagged = score >= self.threshold
        return Verdict(
            flagged=flagged,
            score=score,
            backend=self.backend,
            reason_code="injection_suspected" if flagged else None,
            cost_usd=reply.cost_usd,
        )


def qualify(judge: JudgeDetector, golden: Path) -> tuple[int, int]:
    """``(passed, n)`` over ``{"text": ..., "injection": bool}`` lines; a judge error fails its case."""
    cases = [
        json.loads(line) for line in golden.read_text(encoding="utf-8").splitlines() if line.strip()
    ]
    passed = 0
    for case in cases:
        v = injection_check(judge, case["text"], "golden")
        passed += v.reason_code != "guard_unavailable" and v.flagged == case["injection"]
    return passed, len(cases)
