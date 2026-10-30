"""Action contracts (``actions/<id>.yaml``) and the effective risk class."""

from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from bhovix_core.models import RiskClass

_ORDER: list[RiskClass] = ["read_only", "reversible", "sign_off"]


class ExecutorSpec(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    kind: Literal["http"]
    system: str
    operation: str  # "METHOD /path/{field}"
    lookup_operation: str | None = None
    secret_name: str


class ActionContract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    id: str
    version: int
    description: str
    input_schema: dict[str, Any]
    risk_class: RiskClass
    targets_production: bool
    changes_spend: bool
    executor: ExecutorSpec
    idempotency_header: str = "Idempotency-Key"
    verify_check: str
    rollback: str | None = None
    rollback_test: str | None = None
    chain_id: str
    expected_outcome: str


def effective_class(contract: ActionContract, data_class: str) -> RiskClass:
    """Raise one level per risk flag; a reversible action with no rollback is sign_off. Never lowers."""
    level = _ORDER.index(contract.risk_class)
    level += contract.targets_production + contract.changes_spend
    level += data_class in {"confidential", "restricted"}
    cls = _ORDER[min(level, 2)]
    if cls == "reversible" and contract.rollback is None:
        cls = "sign_off"
    return cls


_TYPES = {"string": str, "integer": int, "boolean": bool, "object": dict, "array": list}
_KEYWORDS = {
    "type",
    "enum",
    "maxLength",
    "minLength",
    "pattern",
    "properties",
    "required",
    "additionalProperties",
}


def schema_problems(schema: Any, where: str = "input_schema") -> list[str]:
    """Load-time check: only the subset ``schema_errors`` understands, so a contract can't crash the gate."""
    if not isinstance(schema, dict):
        return [f"{where}: must be a mapping"]
    out = [f"{where}: unsupported keyword {k}" for k in schema if k not in _KEYWORDS]
    if "type" in schema and schema["type"] not in _TYPES:
        out.append(f"{where}: unsupported type {schema['type']!r} (use string for numbers)")
    if "pattern" in schema:
        try:
            re.compile(schema["pattern"])
        except (re.error, TypeError):
            out.append(f"{where}: bad pattern")
    for k, sub in (schema.get("properties") or {}).items():
        out += schema_problems(sub, f"{where}.{k}")
    return out


def schema_errors(schema: dict[str, Any], value: Any) -> list[str]:
    """Small JSON-Schema subset: object/required/properties/additionalProperties, type, maxLength, pattern, enum.

    ponytail: subset only; swap for the jsonschema package if a contract needs more keywords.
    """
    errs: list[str] = []
    want = schema.get("type")
    if (
        want
        and not isinstance(value, _TYPES[want])
        or (want == "integer" and isinstance(value, bool))
    ):
        return [f"expected {want}"]
    if "enum" in schema and value not in schema["enum"]:
        errs.append("not in enum")
    if isinstance(value, str):
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            errs.append("too long")
        if "minLength" in schema and len(value) < schema["minLength"]:
            errs.append("too short")
        if "pattern" in schema and not re.fullmatch(schema["pattern"], value):
            errs.append("pattern mismatch")
    if isinstance(value, dict):
        props = schema.get("properties", {})
        errs += [f"missing {k}" for k in schema.get("required", []) if k not in value]
        if schema.get("additionalProperties") is False:
            errs += [f"unexpected {k}" for k in value if k not in props]
        for k, sub in props.items():
            if k in value:
                errs += [f"{k}: {e}" for e in schema_errors(sub, value[k])]
    return errs
