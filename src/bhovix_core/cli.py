"""bhovix-core CLI.

  bhovix-core gate <agent> [--config DIR]              exit 0 when green, 1 when below the threshold
  bhovix-core limits stop|reset --by WHO [--config DIR]  audited

``--config`` overrides ``BHOVIX_CONFIG_DIR``. From a source checkout use ``uv run python -m bhovix_core.cli`` so
the current folder (and its check modules) is importable.
"""

from __future__ import annotations

import argparse
import os
import sys

from bhovix_core import evals
from bhovix_core.app import make_llm
from bhovix_core.audit import LocalDirSink
from bhovix_core.config import load_config
from bhovix_core.limits import Limits
from bhovix_core.registry import load_registry
from bhovix_core.store import MemoryStore


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="bhovix-core")
    p.add_argument("--config", help="client config folder (overrides BHOVIX_CONFIG_DIR)")
    sub = p.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("gate", help="run an agent's golden set")
    g.add_argument("agent")
    lim = sub.add_parser("limits", help="kill switch")
    lim.add_argument("action", choices=["stop", "reset"])
    lim.add_argument("--by", required=True)
    args = p.parse_args(argv)
    if args.config:
        os.environ["BHOVIX_CONFIG_DIR"] = args.config
    cfg = load_config()
    reg = load_registry(cfg)

    if args.cmd == "gate":
        run = evals.gate(reg, make_llm(cfg), args.agent)
        print(
            f"{run.agent_id}: {run.passed}/{run.n} = {run.pass_rate:.2f} "
            f"(threshold {run.threshold:.2f}) -> {'GREEN' if run.green else 'RED'}"
        )
        return 0 if run.green else 1

    # ponytail: the memory store lives in one process, so stop/reset here only audits and sets this
    # process's switch; it becomes a shared switch when the Postgres store arrives.
    limits = Limits(MemoryStore(), LocalDirSink(cfg.audit_dir), reg)
    (limits.stop if args.action == "stop" else limits.reset)(args.by)
    print(f"kill switch {args.action} by {args.by} (audited)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
