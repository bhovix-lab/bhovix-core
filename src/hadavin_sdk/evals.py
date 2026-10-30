"""Evals gate: run an agent's golden set, grade by exact field match, append a green run to qualified.jsonl.

An agent with no green run for its current (model id, prompt hash, config hash) cannot start.
"""

from __future__ import annotations

import hashlib
import json
import os

from hadavin_sdk.config import confined
from hadavin_sdk.guard import judge
from hadavin_sdk.llm.protocol import LLM
from hadavin_sdk.models import GateRun
from hadavin_sdk.registry import Registry

_ASK = "Process the attached request document."
QUALIFIED = "qualified.jsonl"


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
    # An llm_judge is qualified by its own golden set on the same model client (design 4.3).
    # ponytail: judge.jsonl is not in golden_sha256 yet; add it when a client weakens one in practice.
    for d in cfg.backends.detector:
        if d.kind == "llm_judge":
            ok, total = judge.qualify(
                judge.JudgeDetector(llm, d.route, d.threshold),
                confined(cfg.golden_dir, "judge.jsonl"),
            )
            passed, n = passed + ok, n + total
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
    if run.green:  # append-only log: one green run per line
        path = cfg.root / QUALIFIED
        torn = path.exists() and path.stat().st_size > 0 and not path.read_bytes().endswith(b"\n")
        with open(path, "a", encoding="utf-8") as f:
            # A torn tail (disk full mid-append) is closed off, so the new record is its own whole line.
            f.write(("\n" if torn else "") + run.model_dump_json() + "\n")
            f.flush()
            os.fsync(f.fileno())
    return run
