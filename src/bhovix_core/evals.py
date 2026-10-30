"""Evals gate: run an agent's golden set, grade by exact field match, append a green run to qualified.json.

An agent with no green run for its current (model id, prompt hash, config hash) cannot start.
"""

from __future__ import annotations

import hashlib
import json

from bhovix_core.config import confined
from bhovix_core.llm.protocol import LLM
from bhovix_core.models import GateRun
from bhovix_core.registry import Registry

_ASK = "Process the attached request document."


def gate(registry: Registry, llm: LLM, agent_id: str) -> GateRun:
    cfg = registry.config
    agent = registry.agents[agent_id]
    golden_path = confined(cfg.golden_dir, f"{agent_id}.jsonl")
    golden_bytes = golden_path.read_bytes()
    cases = [json.loads(line) for line in golden_bytes.decode("utf-8").splitlines() if line.strip()]
    tools = [
        {"name": c.id, "description": c.description, "input_schema": c.input_schema}
        for c in (registry.contracts[a] for a in agent.scope_allowed)
    ]
    passed = 0
    for case in cases:
        reply = llm.chat(
            [{"role": "user", "content": _ASK}],
            system=registry.prompt(agent_id),
            route=agent.model_route,
            tools=tools,
            # input_ref comes from a file: confined to inputs_dir (no "../" or absolute escapes).
            documents=[confined(cfg.inputs_dir, case["input_ref"]).read_bytes()],
        )
        got = (
            {"action": reply.tool_calls[0].name, "inputs": reply.tool_calls[0].input}
            if reply.tool_calls
            else {"action": None, "inputs": {}}
        )
        passed += got == case["expected"]
    n = len(cases)
    rate = passed / n if n else 0.0
    run = GateRun(
        agent_id=agent_id,
        model_id=cfg.routes[agent.model_route].model_id,
        prompt_sha256=registry.prompt_sha256(agent_id),
        config_hash=registry.config_hash(agent_id),
        golden_sha256=hashlib.sha256(golden_bytes).hexdigest(),
        n=n,
        passed=passed,
        pass_rate=rate,
        threshold=cfg.eval_threshold,
        green=n > 0 and rate >= cfg.eval_threshold,
    )
    if run.green:
        path = cfg.root / "qualified.json"
        runs = json.loads(path.read_text(encoding="utf-8")) if path.exists() else []
        runs.append(run.model_dump(mode="json"))
        path.write_text(json.dumps(runs, indent=2), encoding="utf-8")
    return run
