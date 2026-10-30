"""Verify and rollback functions for the fixture contracts. ``call`` is the executor's caller: it adds the
token, so these functions never see the secret."""

from bhovix_core.models import RunResult


def verify_record(plan, result, call) -> bool:
    status, rec = call("GET", f"/records/{result.external_ref}")
    return (
        status == 200
        and rec.get("title") == plan.inputs.get("title")
        and rec.get("amount") == plan.inputs.get("amount")
    )


def verify_found(plan, result, call) -> bool:
    status, _ = call("GET", f"/records/{plan.inputs['id']}")
    return status == 200


def verify_deleted(plan, result, call) -> bool:
    status, _ = call("GET", f"/records/{plan.inputs['id']}")
    return status == 404


def delete_draft_record(plan, result, call) -> RunResult:
    status, _ = call("DELETE", f"/records/{result.external_ref}")
    if status == 200:
        return RunResult(outcome="succeeded", external_ref=result.external_ref)
    return RunResult(outcome="failed", error_code=f"http_{status}")
