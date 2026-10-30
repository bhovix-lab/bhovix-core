"""The backend table: every capability, its kinds, each kind's settings model and its factory.

Factories are ``"module:function"`` strings, imported only when that kind is built, so a kind whose optional
extra is not installed fails at start-up with the install hint, and nothing else pays for it. This module
imports no other Hadavin module (``config`` imports it).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, model_validator


class KindSettings(BaseModel):
    """One backend entry, ``{kind: <name>, …settings}``. A typo in a setting fails at start-up."""

    # A mistyped key may hold a secret: errors name the field, never its value.
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)
    kind: str


class FakeLLMSettings(KindSettings):
    recorded_dir: Path


class RegexSettings(KindSettings):
    threshold: float = Field(default=0.5, ge=0.0, le=1.0)


class LocalDirSettings(KindSettings):
    dir: Path


class PostgresSettings(KindSettings):
    dsn_secret_name: str
    iam_auth: bool = (
        False  # RDS IAM login: no database password anywhere (needs the `aws` extra too)
    )
    region: str | None = None

    @model_validator(mode="after")
    def _iam_needs_region(self) -> PostgresSettings:
        if self.iam_auth and not self.region:
            raise ValueError("iam_auth needs region (and pip install hadavin-sdk[aws])")
        return self


class FakeChannelSettings(KindSettings):
    signing_secret_name: str | None = None


@dataclass(frozen=True)
class Entry:
    settings: type[KindSettings]
    factory: str  # "module:function", called as function(settings, deps)
    extra: str | None = None  # pip extra the factory module needs: hadavin-sdk[<extra>]


_BUILTIN = "hadavin_sdk.backends.builtin"

# Build order (design §4.2): each capability may use only what is built before it, as ALLOWED says.
TABLE: dict[str, dict[str, Entry]] = {
    "secrets": {"fake": Entry(KindSettings, f"{_BUILTIN}:fake_secrets")},
    "store": {
        "memory": Entry(KindSettings, f"{_BUILTIN}:memory_store"),
        "postgres": Entry(PostgresSettings, "hadavin_sdk.store.postgres:build", extra="pg"),
    },
    "audit": {"local_dir": Entry(LocalDirSettings, f"{_BUILTIN}:local_dir_audit")},
    "llm": {"fake": Entry(FakeLLMSettings, f"{_BUILTIN}:fake_llm")},
    "detector": {"regex": Entry(RegexSettings, f"{_BUILTIN}:regex_detector")},
    "channel": {"fake": Entry(FakeChannelSettings, f"{_BUILTIN}:fake_channel")},
}

# The Deps fields a factory of each capability may see (besides its own bound `resolve`).
ALLOWED: dict[str, frozenset[str]] = {
    "secrets": frozenset(),
    "store": frozenset(),
    "audit": frozenset({"store"}),
    "llm": frozenset({"routes"}),
    "detector": frozenset({"llm"}),
    "channel": frozenset({"store"}),
}

# Capabilities a config may leave out, and the kind they get.
DEFAULTS: dict[str, str] = {
    "secrets": "fake",
    "store": "memory",
    "detector": "regex",
    "channel": "fake",
}

# Environment table (design §4.6): kinds allowed only in `dev`. The names are policy levels, not deployments
# (an owner-approved exception to the no-hardcoded-environments rule).
DEV_ONLY: frozenset[tuple[str, str]] = frozenset(
    {
        ("llm", "fake"),
        ("channel", "fake"),
        ("secrets", "fake"),
        ("secrets", "env"),
        ("store", "memory"),
        ("audit", "local_dir"),
    }
)
