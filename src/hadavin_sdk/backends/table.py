"""The backend table: every capability, its kinds, each kind's settings model and its factory.

Factories are ``"module:function"`` strings, imported only when that kind is built, so a kind whose optional
extra is not installed fails at start-up with the install hint, and nothing else pays for it. This module
imports no other Hadavin module (``config`` imports it).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, model_validator


class KindSettings(BaseModel):
    """One backend entry, ``{kind: <name>, …settings}``. A typo in a setting fails at start-up."""

    # A mistyped key may hold a secret: errors name the field, never its value.
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)
    kind: str


class FakeLLMSettings(KindSettings):
    recorded_dir: Path


# A name that becomes part of a host name: letters, digits and dashes only.
_NAME = r"^[A-Za-z0-9-]+$"


class _LLMSettings(KindSettings):
    call_timeout_s: float = Field(
        default=60.0, gt=0
    )  # socket timeout, per operation (not a wall clock)
    max_attempts: int = Field(default=3, ge=1, le=10)


class AnthropicSettings(_LLMSettings):
    platform: Literal["api", "vertex", "foundry"]
    api_key_secret_name: str | None = None  # api, foundry
    project_id: str | None = Field(default=None, pattern=_NAME)  # vertex
    region: str | None = Field(default=None, pattern=_NAME)  # vertex
    resource: str | None = Field(
        default=None, pattern=_NAME
    )  # foundry: <resource>.services.ai.azure.com

    @model_validator(mode="after")
    def _platform_fields(self) -> AnthropicSettings:
        need = {
            "api": ["api_key_secret_name"],
            "vertex": ["project_id", "region"],
            "foundry": ["api_key_secret_name", "resource"],
        }[self.platform]
        if missing := [n for n in need if not getattr(self, n)]:
            raise ValueError(f"platform {self.platform} needs: {', '.join(missing)}")
        return self


class BedrockSettings(_LLMSettings):
    region: str = Field(pattern=_NAME)


_LOOPBACK = {"127.0.0.1", "localhost", "::1"}


class OpenAICompatSettings(_LLMSettings):
    base_url: str
    api_key_secret_name: str | None = None  # a local Ollama needs none
    # OpenAI reasoning models refuse `max_tokens` and want `max_completion_tokens`.
    max_completion_tokens: bool = False

    @model_validator(mode="after")
    def _https_or_keyless_loopback(self) -> OpenAICompatSettings:
        url = urlsplit(self.base_url)
        local = url.scheme == "http" and url.hostname in _LOOPBACK
        if url.scheme != "https" and not (local and not self.api_key_secret_name):
            raise ValueError(
                "base_url must be https (plain http only to this machine, with no key)"
            )
        return self


class GeminiSettings(_LLMSettings):
    api_key_secret_name: str


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
    # None: `require` for any non-local host (and always with iam_auth); loopback and sockets keep the DSN's.
    sslmode: Literal["disable", "allow", "prefer", "require", "verify-ca", "verify-full"] | None = (
        None
    )

    @model_validator(mode="after")
    def _iam_needs_region(self) -> PostgresSettings:
        if self.iam_auth and not self.region:
            raise ValueError("iam_auth needs region (and pip install hadavin-sdk[aws])")
        return self


class EnvSecretsSettings(KindSettings):
    prefix: str = Field(default="HADAVIN_SECRET_", min_length=1)


class AwsSecretsManagerSettings(KindSettings):
    region: str
    ttl_s: float = Field(default=300, ge=0)  # 0 = no cache


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
_UNVERIFIED = "slice2-unverified"

# Build order (design §4.2): each capability may use only what is built before it, as ALLOWED says.
TABLE: dict[str, dict[str, Entry]] = {
    "secrets": {
        "fake": Entry(KindSettings, f"{_BUILTIN}:fake_secrets"),
        "env": Entry(
            EnvSecretsSettings, "hadavin_sdk.actions.secrets_env:build", status=_UNVERIFIED
        ),
        "aws_secrets_manager": Entry(
            AwsSecretsManagerSettings,
            "hadavin_sdk.actions.secrets_aws:build",
            extra="aws",
            status=_UNVERIFIED,
        ),
    },
    "store": {
        "memory": Entry(KindSettings, f"{_BUILTIN}:memory_store"),
        "postgres": Entry(
            PostgresSettings, "hadavin_sdk.store.postgres:build", extra="pg", status=_UNVERIFIED
        ),
    },
    "audit": {"local_dir": Entry(LocalDirSettings, f"{_BUILTIN}:local_dir_audit")},
    "llm": {
        "fake": Entry(FakeLLMSettings, f"{_BUILTIN}:fake_llm"),
        # Every kind below is slice2-unverified until its P9 live run (design 12.1).
        "anthropic": Entry(AnthropicSettings, "hadavin_sdk.llm.anthropic:make", "anthropic"),
        "bedrock": Entry(BedrockSettings, "hadavin_sdk.llm.bedrock:make", "aws"),
        "openai_compat": Entry(OpenAICompatSettings, "hadavin_sdk.llm.openai_compat:make"),
        "gemini": Entry(GeminiSettings, "hadavin_sdk.llm.gemini:make"),
    },
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
