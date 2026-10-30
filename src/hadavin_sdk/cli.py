"""hadavin-sdk CLI.

  hadavin-sdk gate <agent> [--config DIR]              exit 0 when green, 1 when below the threshold
  hadavin-sdk limits stop|reset --by WHO [--config DIR]  refused until a shared store exists (exit 2)

``--config`` overrides ``HADAVIN_CONFIG_DIR``. From a source checkout use ``uv run python -m hadavin_sdk.cli`` so
the current folder (and its check modules) is importable.
"""

from __future__ import annotations

import argparse
import os
import sys

from hadavin_sdk import evals
from hadavin_sdk.app import make_llm
from hadavin_sdk.audit import AuditUnavailable
from hadavin_sdk.config import load_config
from hadavin_sdk.limits import Limits
from hadavin_sdk.registry import load_registry


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="hadavin-sdk")
    p.add_argument("--config", help="client config folder (overrides HADAVIN_CONFIG_DIR)")
    sub = p.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("gate", help="run an agent's golden set")
    g.add_argument("agent")
    lim = sub.add_parser("limits", help="kill switch")
    lim.add_argument("action", choices=["stop", "reset"])
    lim.add_argument("--by", required=True)
    args = p.parse_args(argv)
    if args.config:
        os.environ["HADAVIN_CONFIG_DIR"] = args.config
    cfg = load_config()
    reg = load_registry(cfg)

    if args.cmd == "gate":
        run = evals.gate(reg, make_llm(cfg), args.agent)
        print(
            f"{run.agent_id}: {run.passed}/{run.n} = {run.pass_rate:.2f} "
            f"(threshold {run.threshold:.2f}) -> {'GREEN' if run.green else 'RED'}"
        )
        return 0 if run.green else 1

    if cfg.backends.store == "memory":
        # The memory store lives inside one running process; a separate CLI process cannot reach it, so
        # claiming "stopped" here would be a lie. Use App.limits.stop() in-process until Postgres arrives.
        print(
            "refused: the kill switch needs a shared store (Postgres). With the memory store, "
            "call app.limits.stop(by=...) inside the running process.",
            file=sys.stderr,
        )
        return 2
    raise NotImplementedError("shared-store kill switch arrives with store.postgres")


def kill_switch(limits: Limits, action: str, by: str) -> int:
    """Run stop/reset for a caller (the CLI once a shared store exists, or an in-process admin hook).

    Exit codes: 0 done; 3 reset refused because the audit store is unavailable (the switch stays ON).
    """
    if action == "stop":
        limits.stop(by)
        print(f"kill switch ON (by {by})")
        return 0
    try:
        limits.reset(by)
    except AuditUnavailable:
        print(
            "refused: the audit store is unavailable, so the reset cannot be recorded. "
            "The kill switch stays ON. Fix the audit store, then try again.",
            file=sys.stderr,
        )
        return 3
    print(f"kill switch OFF (by {by})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
