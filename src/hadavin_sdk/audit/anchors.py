"""What every checkpoint anchor shares: the object name, its body, and the rule for a put that finds the name
taken. A put that finds the same bytes already there is a retry whose first answer was lost, so the
checkpoint *is* anchored; different bytes under the same name mean someone else wrote it: `AnchorConflict`."""

from __future__ import annotations

import json

PREFIX = "anchors/"


class AnchorConflict(RuntimeError):
    """The anchor name holds a different checkpoint: never overwritten, reported."""


def key(seq: int) -> str:
    return f"{PREFIX}{seq:012d}.json"


def body(seq: int, head: str, signature: str) -> bytes:
    return json.dumps({"seq": seq, "hash": head, "signature": signature}, sort_keys=True).encode()


def parse(raw: bytes) -> tuple[int, tuple[str, str]]:
    a = json.loads(raw)
    return int(a["seq"]), (a["hash"], a["signature"])


def already_there(existing: bytes, wanted: bytes, seq: int) -> None:
    if existing != wanted:
        raise AnchorConflict(f"anchor {seq} already holds a different checkpoint")
