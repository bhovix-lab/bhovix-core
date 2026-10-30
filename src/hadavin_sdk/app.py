"""App wiring: builds every module from one client config and connects runtime, approvals and executor.

This is the only place that hands the secret provider to the executor; runtime gets bound callables.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from hadavin_sdk.actions.executor import Executor
from hadavin_sdk.actions.secrets import SecretProvider
from hadavin_sdk.approvals import Approvals, Channel
from hadavin_sdk.audit import AuditSink
from hadavin_sdk.backends import make, platform_secrets
from hadavin_sdk.config import Config, load_config
from hadavin_sdk.guard.injection import Detector
from hadavin_sdk.limits import Limits
from hadavin_sdk.models import now
from hadavin_sdk.registry import Registry, load_registry
from hadavin_sdk.runtime.agent_loop import Hooks, Runtime
from hadavin_sdk.store import Store


@dataclass
class App:
    config: Config
    registry: Registry
    store: Store
    audit: AuditSink
    limits: Limits
    executor: Executor
    approvals: Approvals
    runtime: Runtime


def build(
    config_dir: Path | None,
    agents: list[str],
    *,
    secrets: SecretProvider | None = None,
    channel: Channel | None = None,
    detector: Detector | None = None,
    clock: Callable[[], datetime] = now,
    timeout_s: float = 10.0,
) -> App:
    """Build every backend from the config's table entries, in the design 4.2 order. The keyword overrides
    replace one configured backend (tests); `secrets` replaces the configured provider for both the executor
    and the backends' own secrets. Missing or shared secret names fail here, before the first run."""
    cfg = load_config(config_dir)
    reg = load_registry(cfg)
    b = cfg.backends
    secrets = secrets or make("secrets", b.secrets)
    executor_names = {c.executor.secret_name for c in reg.contracts.values()}
    platform_secrets.check(secrets, [s for _, s in b.entries()], executor_names)
    signer = make("signer", b.signer, secrets)
    store = make("store", b.store, secrets)
    audit = make("audit", b.audit, secrets, store=store, signer=signer)
    llm = make("llm", b.llm, secrets, routes=cfg.routes)
    detector = detector or make("detector", b.detector[0], secrets, llm=llm)
    channel = channel or make("channel", b.channel, secrets, store=store)
    limits = Limits(store, audit, reg)
    executor = Executor(reg, secrets, timeout_s=timeout_s)
    holder: dict[str, Runtime] = {}
    approvals = Approvals(
        store,
        audit,
        reg,
        channel,
        lambda run_id, status, d: holder["rt"].on_decided(run_id, status, d),
        clock,
        detector,
    )
    hooks = Hooks(
        request_approval=approvals.request,
        execute=executor.execute,
        verify=executor.verify,
        rollback=executor.rollback,
    )
    runtime = Runtime(
        reg,
        store,
        audit,
        llm,
        detector,
        limits,
        agents,
        hooks,
    )
    holder["rt"] = runtime
    return App(cfg, reg, store, audit, limits, executor, approvals, runtime)
