"""Client config: ``HADAVIN_CONFIG_DIR`` names a folder holding ``config.yaml`` and friends.

Bad config fails at start-up. Cross-file checks (agents, actions, chains) live in ``registry``.
"""

from __future__ import annotations

from decimal import Decimal
from pathlib import Path
from typing import Annotated, Literal
from urllib.parse import urlsplit

import yaml
from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class ConfigError(ValueError):
    """The client config is invalid; the process must not start."""


def _money(v: object) -> object:
    if isinstance(v, float):
        # ValueError, not TypeError: pydantic turns only ValueError into a validation error.
        raise ValueError("money must be a decimal string, not a float")  # noqa: TRY004
    return v


Money = Annotated[Decimal, BeforeValidator(_money)]

AWS_BACKENDS = {"bedrock", "bedrock_guardrail"}
REAL_BACKENDS = AWS_BACKENDS | {"slack"}


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Route(_Strict):
    model_id: str
    input_usd_per_mtok: Money
    output_usd_per_mtok: Money
    max_tokens: int = Field(gt=0)


class Backends(_Strict):
    llm: Literal["fake", "bedrock"] = "fake"
    store: Literal["memory"] = "memory"
    audit: Literal["local_dir"] = "local_dir"
    channel: Literal["fake", "slack"] = "fake"
    detector: Literal["regex", "bedrock_guardrail"] = "regex"

    def names(self) -> set[str]:
        return {self.llm, self.store, self.audit, self.channel, self.detector}


_LOOPBACK = {"127.0.0.1", "localhost", "::1"}


def url_allowed(url: str, allow_insecure_loopback: bool) -> bool:
    """The bearer token travels with every call: https only. Plain http only to this machine, and only when
    the config sets ``allow_insecure_loopback: true`` (the local test fixture). Used at load and at call time."""
    parts = urlsplit(url)
    if parts.scheme == "https":
        return True
    return parts.scheme == "http" and allow_insecure_loopback and parts.hostname in _LOOPBACK


class System(_Strict):
    base_url: str


class SlackConfig(_Strict):
    signing_secret_name: str
    bot_token_name: str
    channel_id: str


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="HADAVIN_")
    config_dir: Path


class Config(_Strict):
    routes: dict[str, Route]
    backends: Backends = Backends()
    region: str | None = None
    audit_dir: Path
    recorded_dir: Path
    golden_dir: Path
    inputs_dir: Path
    detector_threshold: float = Field(ge=0.0, le=1.0)
    eval_threshold: float = Field(default=1.0, ge=0.0, le=1.0)
    check_modules: list[str] = []
    systems: dict[str, System] = {}
    slack: SlackConfig | None = None
    egress_hosts: frozenset[str] = frozenset()
    allow_insecure_loopback: bool = False  # true only in the local test fixture config
    root: Path

    @model_validator(mode="after")
    def _cross_checks(self) -> Config:
        for name, system in self.systems.items():
            if not url_allowed(system.base_url, self.allow_insecure_loopback):
                raise ValueError(
                    f"system {name}: base_url must be https "
                    f"(http only for loopback with allow_insecure_loopback): {system.base_url}"
                )
        names = self.backends.names()
        if names & AWS_BACKENDS and not self.region:
            raise ValueError("region is required when an AWS backend is set")
        if names & REAL_BACKENDS and not self.egress_hosts:
            raise ValueError("egress.yaml is empty while a real backend is set")
        if self.backends.channel == "slack" and self.slack is None:
            raise ValueError("slack settings are required when channel is slack")
        return self


def _read_yaml(path: Path) -> dict:
    if not path.exists():
        return {}
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ConfigError(f"{path.name}: expected a mapping at the top level")
    return data


def confined(base: Path, relative: str) -> Path:
    """``base / relative``, refused if it resolves outside ``base`` (no ``..`` or absolute escapes)."""
    root = Path(base).resolve()
    path = (root / relative).resolve()
    if not path.is_relative_to(root):
        raise ConfigError(f"path escapes its folder: {relative}")
    return path


def load_config(config_dir: Path | None = None) -> Config:
    """Every start-up problem (missing HADAVIN_CONFIG_DIR, bad YAML, bad values) is a ConfigError."""
    try:
        root = Path(config_dir) if config_dir else Settings().config_dir  # type: ignore[call-arg]
        raw = _read_yaml(root / "config.yaml")
        egress = _read_yaml(root / "egress.yaml").get("hosts") or []
        for key in ("audit_dir", "recorded_dir", "golden_dir", "inputs_dir"):
            if key in raw:
                raw[key] = root / raw[key]
        return Config(**raw, egress_hosts=frozenset(egress), root=root)
    except ConfigError:
        raise
    except (ValueError, TypeError, yaml.YAMLError) as exc:  # pydantic errors are ValueErrors
        raise ConfigError(str(exc)) from exc
