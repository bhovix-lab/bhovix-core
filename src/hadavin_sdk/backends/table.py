"""The backend table: every capability, its kinds, each kind's settings model and its factory.

Factories are ``"module:function"`` strings, imported only when that kind is built, so a kind whose optional
extra is not installed fails at start-up with the install hint, and nothing else pays for it. This module
imports no other Hadavin module (``config`` imports it).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


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


class S3ObjectLockSettings(KindSettings):
    """The chain's anchor. COMPLIANCE only in prod with `retention_ack` (the client agreed retention in
    writing); prod also needs the ack for GOVERNANCE (config.py, environment table)."""

    kind: Literal["s3_object_lock"]
    bucket: str
    region: str
    mode: Literal["GOVERNANCE", "COMPLIANCE"] = "GOVERNANCE"
    retain_days: int = Field(default=1, ge=1)
    retention_ack: bool = False


class ChainSettings(KindSettings):
    anchor: S3ObjectLockSettings | None = None
    checkpoint_every: int = Field(default=100, ge=1)


class Ed25519LocalSettings(KindSettings):
    private_key_path: Path
    passphrase_secret_name: str | None = None


class AwsKmsSettings(KindSettings):
    key_id: str
    region: str


class FakeChannelSettings(KindSettings):
    signing_secret_name: str | None = None


@dataclass(frozen=True)
class Entry:
    settings: type[KindSettings]
    factory: str  # "module:function", called as function(settings, deps)
    extra: str | None = None  # pip extra the factory module needs: hadavin-sdk[<extra>]
    # Design 0: "have" (slice 1), "slice2" (suite + one live run), "slice2-unverified" (suite on fakes only).
    status: str = "have"


_BUILTIN = "hadavin_sdk.backends.builtin"
_SIGNER = "hadavin_sdk.audit.signer"
_UNVERIFIED = "slice2-unverified"

# Build order (design §4.2): each capability may use only what is built before it, as ALLOWED says.
TABLE: dict[str, dict[str, Entry]] = {
    "secrets": {"fake": Entry(KindSettings, f"{_BUILTIN}:fake_secrets")},
    "signer": {
        "none": Entry(KindSettings, f"{_BUILTIN}:no_signer"),
        "ed25519_local": Entry(
            Ed25519LocalSettings, f"{_SIGNER}:build_local", extra="signer", status=_UNVERIFIED
        ),
        "aws_kms": Entry(AwsKmsSettings, f"{_SIGNER}:build_kms", extra="aws", status=_UNVERIFIED),
    },
    "store": {"memory": Entry(KindSettings, f"{_BUILTIN}:memory_store")},
    "audit": {
        "local_dir": Entry(LocalDirSettings, f"{_BUILTIN}:local_dir_audit"),
        "chain": Entry(
            ChainSettings, "hadavin_sdk.audit.chain:build", extra="signer", status=_UNVERIFIED
        ),
    },
    "llm": {"fake": Entry(FakeLLMSettings, f"{_BUILTIN}:fake_llm")},
    "detector": {"regex": Entry(RegexSettings, f"{_BUILTIN}:regex_detector")},
    "channel": {"fake": Entry(FakeChannelSettings, f"{_BUILTIN}:fake_channel")},
}

# The Deps fields a factory of each capability may see (besides its own bound `resolve`).
ALLOWED: dict[str, frozenset[str]] = {
    "secrets": frozenset(),
    "signer": frozenset(),
    "store": frozenset(),
    "audit": frozenset({"store", "signer"}),
    "llm": frozenset({"routes"}),
    "detector": frozenset({"llm"}),
    "channel": frozenset({"store"}),
}

# Capabilities a config may leave out, and the kind they get.
DEFAULTS: dict[str, str] = {
    "secrets": "fake",
    "signer": "none",
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
# Kinds refused only in `prod` (design 4.6); the anchor rules are in config.py.
NOT_PROD: frozenset[tuple[str, str]] = frozenset({("signer", "ed25519_local")})
