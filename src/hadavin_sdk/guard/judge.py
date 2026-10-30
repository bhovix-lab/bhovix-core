"""``llm_judge``: a model screens untrusted text for injection (design 4.3, 12.1; kept by the owner).

The only cloud-agnostic detector: it runs on any configured llm route. Minimal on purpose: one fixed, versioned
prompt (``judge_prompt.md``, its hash is in ``config_hash``), a forced JSON verdict, metered (the cost rides on the
Verdict and the caller charges it), qualified by its own golden set (``golden_dir/judge.jsonl``, run by the evals
gate). A tripwire OR-ed with the others, never the default: the judge reads attacker text, so it can itself be
steered, and a "clean" from it never clears anything.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from hadavin_sdk.guard.injection import injection_check
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
        answer = reply.tool_calls[0].input if reply.tool_calls else json.loads(reply.text)
        injection, confidence = answer["injection"], answer["confidence"]
        # Anything off-schema raises, and injection_check turns that into a flag (fail closed).
        if not isinstance(injection, bool) or not 0 <= float(confidence) <= 1:
            raise ValueError("judge answer off schema")
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
        passed += v.backend == judge.backend and v.flagged == case["injection"]
    return passed, len(cases)
