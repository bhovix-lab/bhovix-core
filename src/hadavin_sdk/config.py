"""Client config: ``HADAVIN_CONFIG_DIR`` names a folder holding ``config.yaml`` and friends.

Bad config fails at start-up. Cross-file checks (agents, actions, chains) live in ``registry``.
"""

from __future__ import annotations

from decimal import Decimal
from pathlib import Path
from typing import Annotated, Any, Literal, get_args
from urllib.parse import urlsplit

import yaml
from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, ValidationError, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from hadavin_sdk.backends.table import DEFAULTS, DEV_ONLY, NOT_PROD, TABLE, KindSettings
from hadavin_sdk.errors import ConfigError

__all__ = ["Backends", "Config", "ConfigError", "Route", "confined", "load_config", "url_allowed"]


def _money(v: object) -> object:
    if isinstance(v, float):
        # ValueError, not TypeError: pydantic turns only ValueError into a validation error.
        raise ValueError("money must be a decimal string, not a float")  # noqa: TRY004
    return v


Money = Annotated[Decimal, BeforeValidator(_money)]


class _Strict(BaseModel):
    # A mistyped key may hold a secret: errors name the field, never its value.
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)


class Route(_Strict):
    model_id: str
    input_usd_per_mtok: Money
    output_usd_per_mtok: Money
    max_tokens: int = Field(gt=0)


class Backends(_Strict):
    """One validated settings model per capability (built by `parse_backends`, never from raw YAML)."""

    secrets: KindSettings
    signer: KindSettings
    store: KindSettings
    audit: KindSettings
    llm: KindSettings
    detector: tuple[KindSettings, ...]
    channel: KindSettings

    def entries(self) -> list[tuple[str, KindSettings]]:
        out = [(cap, getattr(self, cap)) for cap in TABLE if cap != "detector"]
        return out + [("detector", d) for d in self.detector]


# Slice 1 keys, refused with the place they moved to (design 12.3; no clients yet, so no migration shim).
MOVED = {
    "region": "backends.<capability>.region on each AWS kind",
    "slack": "backends.channel: {kind: slack, channel_id, signing_secret_name, bot_token_secret_name}",
    "detector_threshold": "backends.detector: [{kind: regex, threshold}]",
    "audit_dir": "backends.audit: {kind: local_dir, dir}",
    "recorded_dir": "backends.llm: {kind: fake, recorded_dir}",
}


def _one(cap: str, raw: Any, root: Path) -> KindSettings:
    bare = isinstance(raw, str)
    if bare:
        raw = {"kind": raw}
    if not isinstance(raw, dict) or not isinstance(raw.get("kind"), str):
        raise ConfigError(f"backends.{cap}: expected {{kind: <name>, ...settings}}")
    kinds = TABLE[cap]
    kind = raw["kind"]
    if kind not in kinds:
        raise ConfigError(
            f"backend {cap}: unknown kind {kind!r}; known: {', '.join(sorted(kinds))}"
        )
    model = kinds[kind].settings
    required = [n for n, f in model.model_fields.items() if f.is_required() and n != "kind"]
    if bare and required:
        raise ConfigError(
            f"backends.{cap}: {kind!r} needs settings; "
            f"write backends.{cap}: {{kind: {kind}, {', '.join(required)}}}"
        )
    data = dict(raw)
    for (
        name,
        field,
    ) in model.model_fields.items():  # relative paths are relative to the config folder
        if Path in (field.annotation, *get_args(field.annotation)) and isinstance(
            data.get(name), str
        ):
            data[name] = root / data[name]
    try:
        return model(**data)
    except ValidationError as exc:
        raise ConfigError(f"backends.{cap} ({kind}): {exc}") from exc


def parse_backends(raw: Any, root: Path) -> Backends:
    if raw is not None and not isinstance(raw, dict):
        raise ConfigError("backends: expected a mapping of capability to {kind: ...}")
    raw = dict(raw or {})
    if unknown := set(raw) - set(TABLE):
        raise ConfigError(
            f"backends: unknown capability {sorted(unknown)}; known: {', '.join(TABLE)}"
        )
    if missing := [cap for cap in TABLE if cap not in raw and cap not in DEFAULTS]:
        raise ConfigError(f"backends: {', '.join(missing)} must be set")
    built: dict[str, Any] = {}
    for cap in TABLE:
        value = raw.get(cap, DEFAULTS.get(cap))
        if cap == "detector":
            items = value if isinstance(value, list) else [value]
            if not items:  # every entry runs and any flag flags the run (guard.injection.AnyOf)
                raise ConfigError("backends.detector: list at least one detector")
            built[cap] = tuple(_one(cap, item, root) for item in items)
            if all(d.kind == "llm_judge" for d in built[cap]):
                # The judge reads attacker text and can be steered to say "clean": a tripwire beside
                # another detector, never the only one (design 4.3, 10).
                raise ConfigError("backends.detector: llm_judge needs another detector beside it")
        else:
            built[cap] = _one(cap, value, root)
    return Backends(**built)


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


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="HADAVIN_")
    config_dir: Path


class Config(_Strict):
    environment: Literal["dev", "pilot", "prod"]
    routes: dict[str, Route]
    backends: Backends
    golden_dir: Path
    inputs_dir: Path
    eval_threshold: float = Field(
        default=1.0, gt=0.0, le=1.0
    )  # 0 would qualify an agent that passed nothing
    check_modules: list[str] = []
    systems: dict[str, System] = {}
    egress_hosts: frozenset[str] = frozenset()
    allow_insecure_loopback: bool = False  # true only in the local test fixture config
    root: Path

    @model_validator(mode="after")
    def _cross_checks(self) -> Config:
        for d in self.backends.detector:  # llm_judge names a route
            if getattr(d, "route", None) is not None and d.route not in self.routes:
                raise ValueError(f"backends.detector {d.kind}: unknown route {d.route!r}")
        for name, system in self.systems.items():
            if not url_allowed(system.base_url, self.allow_insecure_loopback):
                raise ValueError(
                    f"system {name}: base_url must be https "
                    f"(http only for loopback with allow_insecure_loopback): {system.base_url}"
                )
        if self.environment != "dev":  # environment table, design 4.6
            refused = [
                f"{c}: {s.kind}" for c, s in self.backends.entries() if (c, s.kind) in DEV_ONLY
            ]
            refused += ["allow_insecure_loopback"] if self.allow_insecure_loopback else []
            if refused:
                raise ValueError(
                    f"environment {self.environment}: refused outside dev: {', '.join(refused)}"
                )
        if refused := _anchor_refusals(self.environment, self.backends):
            raise ValueError(f"environment {self.environment}: refused: {', '.join(refused)}")
        return self


def _anchor_refusals(environment: str, b: Backends) -> list[str]:
    """Environment table (design 4.6): prod needs a non-local signer and an anchor whose retention the client
    agreed (`retention_ack`); COMPLIANCE mode (undeletable even by the account root) only then."""
    anchor = getattr(b.audit, "anchor", None)
    refused = []
    if (
        anchor is not None
        and anchor.mode == "COMPLIANCE"
        and not (environment == "prod" and anchor.retention_ack)
    ):
        refused.append("anchor mode COMPLIANCE outside prod or without retention_ack")
    if environment == "prod":
        refused += [f"{c}: {s.kind}" for c, s in b.entries() if (c, s.kind) in NOT_PROD]
        if b.audit.kind == "chain" and (anchor is None or not anchor.retention_ack):
            refused.append("audit chain without an anchor with retention_ack")
    return refused


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
        if moved := [k for k in MOVED if k in raw]:
            raise ConfigError("; ".join(f"{k} moved to {MOVED[k]}" for k in moved))
        for key in ("golden_dir", "inputs_dir"):
            if key in raw:
                raw[key] = root / raw[key]
        raw["backends"] = parse_backends(raw.get("backends"), root)
        return Config(**raw, egress_hosts=frozenset(egress), root=root)
    except ConfigError:
        raise
    except (ValueError, TypeError, yaml.YAMLError) as exc:  # pydantic errors are ValueErrors
        raise ConfigError(str(exc)) from exc
