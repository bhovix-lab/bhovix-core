"""App wiring: builds every module from one client config and connects runtime, approvals and executor.

This is the only place that hands the secret provider to the executor; runtime gets bound callables.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from bhovix_core.actions.executor import Executor
from bhovix_core.actions.secrets import SecretProvider
from bhovix_core.approvals import Approvals, Channel, FakeChannel
from bhovix_core.audit import LocalDirSink
from bhovix_core.config import Config, ConfigError, load_config
from bhovix_core.guard.injection import Detector, RegexDetector
from bhovix_core.limits import Limits
from bhovix_core.llm import LLM, FakeLLM
from bhovix_core.models import now
from bhovix_core.registry import Registry, load_registry
from bhovix_core.runtime.agent_loop import Hooks, Runtime
from bhovix_core.store import MemoryStore


def make_llm(cfg: Config) -> LLM:
    if cfg.backends.llm == "fake":
        return FakeLLM(cfg.recorded_dir, cfg.routes)
    raise ConfigError(f"llm backend {cfg.backends.llm!r} is not built yet (needs the owner's yes)")


def make_detector(cfg: Config) -> Detector:
    if cfg.backends.detector == "regex":
        return RegexDetector(cfg.detector_threshold)
    raise ConfigError(f"detector {cfg.backends.detector!r} is not built yet")


def make_channel(cfg: Config) -> Channel:
    if cfg.backends.channel == "fake":
        return FakeChannel()
    raise ConfigError(f"channel {cfg.backends.channel!r} is not built yet (needs the owner's yes)")


@dataclass
class App:
    config: Config
    registry: Registry
    store: MemoryStore
    audit: LocalDirSink
    limits: Limits
    executor: Executor
    approvals: Approvals
    runtime: Runtime


def build(
    config_dir: Path | None,
    secrets: SecretProvider,
    agents: list[str],
    *,
    channel: Channel | None = None,
    detector: Detector | None = None,
    clock: Callable[[], datetime] = now,
    timeout_s: float = 10.0,
) -> App:
    cfg = load_config(config_dir)
    reg = load_registry(cfg)
    store, audit = MemoryStore(), LocalDirSink(cfg.audit_dir)
    limits = Limits(store, audit, reg)
    executor = Executor(reg, secrets, timeout_s=timeout_s)
    detector = detector or make_detector(cfg)
    holder: dict[str, Runtime] = {}
    approvals = Approvals(
        store,
        audit,
        reg,
        channel or make_channel(cfg),
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
        make_llm(cfg),
        detector,
        limits,
        agents,
        hooks,
    )
    holder["rt"] = runtime
    return App(cfg, reg, store, audit, limits, executor, approvals, runtime)
