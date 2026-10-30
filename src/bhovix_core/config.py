"""Client config: ``BHOVIX_CONFIG_DIR`` names a folder holding ``config.yaml`` and friends.

Bad config fails at start-up. Cross-file checks (agents, actions, chains) live in ``registry``.
"""

from __future__ import annotations

from decimal import Decimal
from pathlib import Path
from typing import Annotated, Literal

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


class System(_Strict):
    base_url: str = Field(pattern=r"^https?://")


class SlackConfig(_Strict):
    signing_secret_name: str
    bot_token_name: str
    channel_id: str


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="BHOVIX_")
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
    root: Path

    @model_validator(mode="after")
    def _cross_checks(self) -> Config:
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
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return data or {}


def load_config(config_dir: Path | None = None) -> Config:
    root = Path(config_dir) if config_dir else Settings().config_dir  # type: ignore[call-arg]
    raw = _read_yaml(root / "config.yaml")
    egress = _read_yaml(root / "egress.yaml").get("hosts", [])
    for key in ("audit_dir", "recorded_dir", "golden_dir", "inputs_dir"):
        if key in raw:
            raw[key] = root / raw[key]
    try:
        return Config(**raw, egress_hosts=frozenset(egress), root=root)
    except (ValueError, TypeError) as exc:
        raise ConfigError(str(exc)) from exc
