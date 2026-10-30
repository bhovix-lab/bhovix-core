"""hadavin-sdk CLI.

  hadavin-sdk [--config DIR] gate <agent>                exit 0 when green, 1 when below the threshold
  hadavin-sdk [--config DIR] limits stop|reset --by WHO  needs a shared store (postgres); memory: exit 2
  hadavin-sdk [--config DIR] tick                       one pass of approvals sweep, reconcile, stuck runs,
                                                         audit checkpoint; exit 0 ok, 1 a step failed,
                                                         2 config error, 3 store unreachable
  hadavin-sdk [--config DIR] migrate [--runtime-role R]  apply the postgres schema; the migration role's DSN
                                                         comes from the HADAVIN_MIGRATE_DSN environment variable
  hadavin-sdk [--config DIR] audit verify                exit 0 intact, 1 not, 2 refused, 3 unreadable

``--config`` goes before the subcommand and overrides ``HADAVIN_CONFIG_DIR``. From a source checkout use ``uv run python -m hadavin_sdk.cli`` so
the current folder (and its check modules) is importable.
"""

from __future__ import annotations

import argparse
import os
import sys

from hadavin_sdk import evals
from hadavin_sdk.audit import AuditUnavailable
from hadavin_sdk.backends import make, platform_secrets
from hadavin_sdk.config import load_config
from hadavin_sdk.errors import ConfigError
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
    sub.add_parser("tick", help="one pass of the housekeeping steps (run every 30-60 s)")
    mig = sub.add_parser("migrate", help="apply the postgres store schema (migration role)")
    mig.add_argument("--runtime-role", help="grant this database role SELECT, INSERT, UPDATE")
    aud = sub.add_parser("audit", help="check the chain audit")
    aud.add_argument("action", choices=["verify"])
    args = p.parse_args(argv)
    if args.config:
        os.environ["HADAVIN_CONFIG_DIR"] = args.config
    if args.cmd == "tick":
        return _tick()
    cfg = load_config()
    if args.cmd == "migrate":
        return _migrate(cfg, args.runtime_role)
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

    b = cfg.backends
    if args.cmd == "audit" and b.audit.kind != "chain":
        print(
            "refused: audit verify reads a chain audit (backends.audit.kind: chain)",
            file=sys.stderr,
        )
        return 2
    if b.store.kind == "memory":
        # The memory store lives inside one running process; a separate CLI process cannot reach it, so
        # claiming "stopped" here would be a lie. Use App.limits.stop() in-process until Postgres arrives.
        what = "audit verify" if args.cmd == "audit" else "the kill switch"
        print(
            f"refused: {what} needs a shared store (Postgres). With the memory store, "
            "use the running process's app (app.limits, app.audit).",
            file=sys.stderr,
        )
        return 2
    try:
        secrets = make("secrets", b.secrets)
        # Same start-up probe as app.build: a missing DSN is a clean ConfigError, not a KeyError mid-build.
        platform_secrets.check(secrets, [b.signer, b.anchor, b.store, b.audit], set())
        signer = make("signer", b.signer, secrets)
        anchor = make("anchor", b.anchor, secrets)
        store = make("store", b.store, secrets)
        audit = make("audit", b.audit, secrets, store=store, signer=signer, anchor=anchor)
    except ConfigError as exc:
        if args.cmd != "audit":
            raise
        # An unreachable or un-migrated store is not evidence of tampering: never exit 1 for it.
        print(f"could not verify: {exc}", file=sys.stderr)
        return 3
    if args.cmd == "audit":
        return audit_verify(audit)
    return kill_switch(Limits(store, audit, reg), args.action, args.by)


def _tick() -> int:
    """Build the app with every qualified agent (an unqualified one must not stop approvals expiring)."""
    from hadavin_sdk.app import build
    from hadavin_sdk.runtime.agent_loop import Unqualified, assert_qualified
    from hadavin_sdk.runtime.tick import run_tick
    from hadavin_sdk.store.protocol import StoreUnavailable

    try:
        reg = load_registry(load_config())
        agents = []
        for agent_id in reg.agents:
            try:
                assert_qualified(reg, agent_id)
                agents.append(agent_id)
            except Unqualified:
                print(
                    f"tick: {agent_id} is not qualified; its new runs are refused", file=sys.stderr
                )
        app = build(None, agents)
    except StoreUnavailable as exc:
        print(f"tick: {exc}", file=sys.stderr)
        return 3
    except ConfigError as exc:
        print(f"tick: config error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001 - any other start-up failure is a config error, never "1"
        print(f"tick: config error: {type(exc).__name__}", file=sys.stderr)
        return 2
    return run_tick(app)


def _migrate(cfg, runtime_role: str | None) -> int:
    store = cfg.backends.store
    if store.kind != "postgres":
        print(
            f"refused: migrate is for the postgres store; this config uses {store.kind!r}",
            file=sys.stderr,
        )
        return 2
    dsn = os.environ.get("HADAVIN_MIGRATE_DSN")
    if not dsn:
        print("refused: set HADAVIN_MIGRATE_DSN to the migration role's DSN", file=sys.stderr)
        return 2
    from hadavin_sdk.store.migrate import migrate
    from hadavin_sdk.store.postgres import ca_file

    ca = ca_file(store, make("secrets", cfg.backends.secrets).get)
    applied = migrate(
        dsn,
        runtime_role=runtime_role,
        iam_auth=store.iam_auth,
        region=store.region,
        sslmode=store.sslmode,
        sslrootcert=ca,
    )
    print(f"applied: {', '.join(applied) or 'nothing (up to date)'}")
    if applied and not runtime_role:
        print(
            "warning: new tables have no runtime grants; run again with --runtime-role <role>",
            file=sys.stderr,
        )
    return 0


def audit_verify(audit) -> int:
    """Recompute the chain, every checkpoint signature and every anchor. Exit 0 intact, 1 not intact,
    3 when the audit or its anchors cannot be read (an outage is not evidence of tampering)."""
    result = audit.verify()
    if result.unreadable:
        print(f"could not verify: {'; '.join(result.problems)}")
        return 3
    print(
        f"{result.rows} rows, signed through row {result.signed_through} "
        f"({result.unsigned_tail} not signed yet)"
    )
    for problem in result.problems:
        print(f"PROBLEM: {problem}")
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
