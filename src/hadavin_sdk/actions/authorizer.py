"""The gate: deterministic (principal, agent, plan) -> allow / needs_approval / deny, with a rule id.

No model output sets the outcome. The first matching row wins.
"""

from __future__ import annotations

from hadavin_sdk.actions.contract import ActionContract, effective_class, schema_errors
from hadavin_sdk.identity import Principal
from hadavin_sdk.models import GateDecision, Plan
from hadavin_sdk.registry import AgentRecord


def authorize(
    principal: Principal,
    agent: AgentRecord,
    contract: ActionContract,
    plan: Plan,
    blocked: list[str],
) -> GateDecision:
    def out(outcome: str, rule: str) -> GateDecision:
        return GateDecision(
            run_id=plan.run_id, plan_hash=plan.hash(), outcome=outcome, rule_id=rule
        )

    if agent.status != "live":
        return out("deny", "agent.not_live")
    if plan.action_id not in agent.scope_allowed:
        return out("deny", "scope.agent")
    if plan.action_id not in principal.rights:
        return out("deny", "scope.principal")
    if schema_errors(contract.input_schema, plan.inputs):
        return out("deny", "input.schema")
    if blocked:
        return out("deny", f"limits.{blocked[0]}")
    cls = effective_class(contract, agent.data_class)
    if cls == "sign_off":
        return out("deny", "class.sign_off.no_stepup")
    if cls == "reversible":
        return out("needs_approval", "class.reversible")
    return out("allow", "class.read_only")
