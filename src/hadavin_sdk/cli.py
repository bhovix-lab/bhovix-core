"""hadavin-sdk CLI.

  hadavin-sdk [--config DIR] gate <agent>                exit 0 when green, 1 when below the threshold
  hadavin-sdk [--config DIR] limits stop|reset --by WHO  refused until a shared store exists (exit 2)
  hadavin-sdk [--config DIR] audit verify                exit 0 when the chain audit is intact, 1 when not

``--config`` goes before the subcommand and overrides ``HADAVIN_CONFIG_DIR``. From a source checkout use ``uv run python -m hadavin_sdk.cli`` so
the current folder (and its check modules) is importable.
"""

from __future__ import annotations

import argparse
import os
import sys

from hadavin_sdk import evals
from hadavin_sdk.audit import AuditUnavailable
from hadavin_sdk.backends import make
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
    aud = sub.add_parser("audit", help="check the chain audit")
    aud.add_argument("action", choices=["verify"])
    args = p.parse_args(argv)
    if args.config:
        os.environ["HADAVIN_CONFIG_DIR"] = args.config
    cfg = load_config()
    reg = load_registry(cfg)

    if args.cmd == "gate":
        b = cfg.backends
        run = evals.gate(
            reg, make("llm", b.llm, make("secrets", b.secrets), routes=cfg.routes), args.agent
        )
        print(
            f"{run.agent_id}: {run.passed}/{run.n} = {run.pass_rate:.2f} "
            f"(threshold {run.threshold:.2f}) -> {'GREEN' if run.green else 'RED'}"
        )
        return 0 if run.green else 1

    if args.cmd == "audit":
        b = cfg.backends
        if b.audit.kind != "chain" or b.store.kind == "memory":
            print(
                "refused: audit verify reads a chain audit in a shared store (Postgres); "
                "a memory store lives inside one running process.",
                file=sys.stderr,
            )
            return 2
        secrets = make("secrets", b.secrets)
        signer = make("signer", b.signer, secrets)
        store = make("store", b.store, secrets)
        return audit_verify(make("audit", b.audit, secrets, store=store, signer=signer))

    if cfg.backends.store.kind == "memory":
        # The memory store lives inside one running process; a separate CLI process cannot reach it, so
        # claiming "stopped" here would be a lie. Use App.limits.stop() in-process until Postgres arrives.
        print(
            "refused: the kill switch needs a shared store (Postgres). With the memory store, "
            "call app.limits.stop(by=...) inside the running process.",
            file=sys.stderr,
        )
        return 2
    raise NotImplementedError("shared-store kill switch arrives with store.postgres")


def audit_verify(audit) -> int:
    """Recompute the chain, every checkpoint signature and every anchor. Exit 0 intact, 1 not."""
    result = audit.verify()
    print(
        f"{result.rows} rows, signed through row {result.signed_through} "
        f"({result.unsigned_tail} not signed yet)"
    )
    for problem in result.problems:
        print(f"TAMPERED: {problem}")
    print("intact" if result.ok else "NOT intact")
    return 0 if result.ok else 1


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
