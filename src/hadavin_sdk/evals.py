"""Evals gate: run an agent's golden set, grade by exact field match, append a green run to qualified.jsonl.

An agent with no green run for its current (model id, prompt hash, config hash) cannot start.
With ``k > 1`` every item runs k times and green needs pass^k (items passing all k runs) at the threshold.
"""

from __future__ import annotations

import json
import math
import os
from decimal import Decimal

from hadavin_sdk.config import ConfigError, confined
from hadavin_sdk.guard import judge
from hadavin_sdk.llm.protocol import LLM
from hadavin_sdk.models import GateRun
from hadavin_sdk.registry import Registry

_ASK = "Process the attached request document."
QUALIFIED = "qualified.jsonl"


def upper_error_bound(x: int, n: int, confidence: float = 0.95) -> float | None:
    """Exact one-sided Clopper-Pearson upper bound on a failure rate after x failures in n items.

    The p at which P(X <= x | n, p) = 1 - confidence, found by bisection (the CDF falls as p rises).
    """
    if n == 0:
        return None
    if not 0 <= x <= n:
        raise ValueError(f"failures {x} outside 0..{n}")
    if x == n:
        return 1.0
    alpha = 1 - confidence

    # In log space: comb(n, i) overflows a float above n of about 1030. Computed once, not per bisection step.
    log_combs = [math.log(math.comb(n, i)) for i in range(x + 1)]

    def cdf(p: float) -> float:
        return sum(
            math.exp(lc + i * math.log(p) + (n - i) * math.log1p(-p))
            for i, lc in enumerate(log_combs)
        )

    lo, hi = 0.0, 1.0
    for _ in range(60):  # 2**-60: far below any reported precision
        mid = (lo + hi) / 2
        lo, hi = (mid, hi) if cdf(mid) > alpha else (lo, mid)
    return hi


def gate(registry: Registry, llm: LLM, agent_id: str, *, k: int = 1) -> GateRun:
    if k < 1:
        raise ConfigError(f"gate k must be at least 1, got {k}")
    cfg = registry.config
    agent = registry.agents[agent_id]
    # The golden set, its documents and judge.jsonl, hashed before the run and again after it: a file that
    # changed while the run read it was not the set it qualifies on, so the run is never green.
    golden_before = registry.golden_sha256(agent_id)
    golden_path = confined(cfg.golden_dir, f"{agent_id}.jsonl")
    golden_bytes = golden_path.read_bytes()
    cases = [json.loads(line) for line in golden_bytes.decode("utf-8").splitlines() if line.strip()]
    tools = [
        {"name": c.id, "description": c.description, "input_schema": c.input_schema}
        for c in (registry.contracts[a] for a in agent.scope_allowed)
    ]
    passed = run_passes = abstains = 0
    cost = Decimal(0)
    for case in cases:
        # input_ref comes from a file: confined to inputs_dir (no "../" or absolute escapes).
        doc = confined(cfg.inputs_dir, case["input_ref"]).read_bytes()
        case_passes = 0
        for _ in range(k):
            reply = llm.chat(
                [{"role": "user", "content": _ASK}],
                system=registry.prompt(agent_id),
                route=agent.model_route,
                tools=tools,
                documents=[doc],
            )
            cost += reply.cost_usd
            abstains += not reply.tool_calls
            got = (
                {"action": reply.tool_calls[0].name, "inputs": reply.tool_calls[0].input}
                if reply.tool_calls
                else {"action": None, "inputs": {}}
            )
            case_passes += got == case["expected"]
        run_passes += case_passes
        passed += case_passes == k  # k == 1: passed; k > 1: passed all k runs
    n = len(cases)
    pairs = n * k
    rate = run_passes / pairs if n else 0.0  # pass@1
    pass_k = passed / n if n and k > 1 else None
    score = pass_k if pass_k is not None else rate
    # An llm_judge is qualified by its own golden set on the same model client, at its own rate (design 4.3):
    # the agent's passes never hide a judge's failures, and an empty judge set qualifies nothing.
    judges_green = True
    for d in cfg.backends.detector:
        if d.kind == "llm_judge":
            path = confined(cfg.golden_dir, "judge.jsonl")
            if not path.is_file():
                raise ConfigError("llm_judge needs its golden set: golden_dir/judge.jsonl")
            ok, total = judge.qualify(judge.JudgeDetector(llm, d.route, d.threshold), path)
            judges_green = judges_green and total > 0 and ok / total >= cfg.eval_threshold
    golden_after = registry.golden_sha256(agent_id)
    run = GateRun(
        agent_id=agent_id,
        model_id=cfg.routes[agent.model_route].model_id,
        prompt_sha256=registry.prompt_sha256(agent_id),
        config_hash=registry.config_hash(agent_id),
        golden_sha256=golden_after,
        n=n,
        passed=passed,
        pass_rate=rate,
        threshold=cfg.eval_threshold,
        # The judge set above runs once per gate call, not k times.
        green=n > 0
        and score >= cfg.eval_threshold
        and judges_green
        and golden_before == golden_after,
        k=k,
        pass_k=pass_k,
        abstain_rate=abstains / pairs if n else None,
        cost_per_task_usd=cost / pairs if n else None,
        upper_error_bound=upper_error_bound(n - passed, n),
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
