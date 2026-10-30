"""Plan builder: turns one proposed tool call into a frozen Plan. The model only proposes."""

from __future__ import annotations

from hadavin_sdk.actions.contract import ActionContract, effective_class
from hadavin_sdk.models import Plan, Run, Target, ToolCall
from hadavin_sdk.registry import AgentRecord


def build_plan(run: Run, agent: AgentRecord, contract: ActionContract, call: ToolCall) -> Plan:
    return Plan(
        run_id=run.run_id,
        agent_id=agent.id,
        action_id=contract.id,
        action_version=contract.version,
        risk_class=effective_class(contract, agent.data_class),
        inputs=dict(call.input),
        target=Target(system=contract.executor.system, ref=call.input.get("id")),
        idempotency_key=f"{run.run_id}:{contract.id}",
        expected_outcome=contract.expected_outcome,
    )
