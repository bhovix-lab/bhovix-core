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


def body(
    seq: int, head: str, signature: str, alg: str | None = None, key_id: str | None = None
) -> bytes:
    """`alg` and `key_id` name the signature scheme and the key that made it, so an auditor holding only the
    anchor objects and a public key needs nothing else to verify them (`chain.verify_anchor_bodies`)."""
    doc = {"seq": seq, "hash": head, "signature": signature}
    if alg is not None:
        doc["alg"] = alg
    if key_id is not None:
        doc["key_id"] = key_id
    return json.dumps(doc, sort_keys=True).encode()


def parse(raw: bytes) -> tuple[int, tuple[str, str]]:
    a = json.loads(raw)
    return int(a["seq"]), (a["hash"], a["signature"])


def already_there(existing: bytes, wanted: bytes, seq: int) -> None:
    if existing != wanted:
        raise AnchorConflict(f"anchor {seq} already holds a different checkpoint")
