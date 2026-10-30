"""The backend table: every capability, its kinds, each kind's settings model and its factory.

Factories are ``"module:function"`` strings, imported only when that kind is built, so a kind whose optional
extra is not installed fails at start-up with the install hint, and nothing else pays for it. This module
imports no other Hadavin module (``config`` imports it).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal
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
    threshold: float = Field(default=0.5, gt=0.0, le=1.0)  # 0 would flag every clean text (score 0)


class JudgeSettings(KindSettings):
    route: str  # a key of `routes`; checked against them at load
    threshold: float = Field(default=0.7, gt=0.0, le=1.0)


class GuardrailSettings(KindSettings):
    guardrail_id: str
    guardrail_version: str
    region: str = Field(pattern=_NAME)
    threshold: float = Field(default=0.5, gt=0.0, le=1.0)


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


class EnvSecretsSettings(KindSettings):
    prefix: str = Field(default="HADAVIN_SECRET_", min_length=1)


class AwsSecretsManagerSettings(KindSettings):
    region: str
    ttl_s: float = Field(default=300, ge=0)  # 0 = no cache


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
    # The hosts this kind's SDK or HTTP client connects to (design 4.5, 12.9): `hadavin_sdk.backends.hosts`
    # builds a suggested egress list from them. None: no network, or a host only a secret names (a DSN).
    hosts: Callable[[Any], list[str]] | None = None


def _aws(service: str) -> Callable[[Any], list[str]]:
    return lambda s: [f"{service}.{s.region}.amazonaws.com"]


def _vertex_host(region: str) -> str:
    """As the anthropic SDK derives Vertex's host (llm/anthropic.py passes the same URL explicitly)."""
    if region == "global":
        return "aiplatform.googleapis.com"
    if region in ("us", "eu"):
        return f"aiplatform.{region}.rep.googleapis.com"
    return f"{region}-aiplatform.googleapis.com"


def _anthropic_hosts(s: Any) -> list[str]:
    if s.platform == "vertex":
        return [_vertex_host(s.region), "oauth2.googleapis.com"]  # plus the Google token endpoint
    if s.platform == "foundry":
        return [f"{s.resource}.services.ai.azure.com"]
    return ["api.anthropic.com"]


def _chain_hosts(s: Any) -> list[str]:
    return [f"{s.anchor.bucket}.s3.{s.anchor.region}.amazonaws.com"] if s.anchor else []


_BUILTIN = "hadavin_sdk.backends.builtin"
_UNVERIFIED = "slice2-unverified"
_SIGNER = "hadavin_sdk.audit.signer"

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
            hosts=_aws("secretsmanager"),
        ),
    },
    "signer": {
        "none": Entry(KindSettings, f"{_BUILTIN}:no_signer"),
        "ed25519_local": Entry(
            Ed25519LocalSettings, f"{_SIGNER}:build_local", extra="signer", status=_UNVERIFIED
        ),
        "aws_kms": Entry(
            AwsKmsSettings,
            f"{_SIGNER}:build_kms",
            extra="aws",
            status=_UNVERIFIED,
            hosts=_aws("kms"),
        ),
    },
    "store": {
        "memory": Entry(KindSettings, f"{_BUILTIN}:memory_store"),
        "postgres": Entry(
            PostgresSettings, "hadavin_sdk.store.postgres:build", extra="pg", status=_UNVERIFIED
        ),
    },
    "audit": {
        "local_dir": Entry(LocalDirSettings, f"{_BUILTIN}:local_dir_audit"),
        "chain": Entry(
            ChainSettings,
            "hadavin_sdk.audit.chain:build",
            extra="signer",
            status=_UNVERIFIED,
            hosts=_chain_hosts,
        ),
    },
    "llm": {
        "fake": Entry(FakeLLMSettings, f"{_BUILTIN}:fake_llm"),
        # Every kind below is slice2-unverified until its P9 live run (design 12.1).
        "anthropic": Entry(
            AnthropicSettings,
            "hadavin_sdk.llm.anthropic:make",
            "anthropic",
            status=_UNVERIFIED,
            hosts=_anthropic_hosts,
        ),
        "bedrock": Entry(
            BedrockSettings,
            "hadavin_sdk.llm.bedrock:make",
            "aws",
            status=_UNVERIFIED,
            hosts=_aws("bedrock-runtime"),
        ),
        "openai_compat": Entry(
            OpenAICompatSettings,
            "hadavin_sdk.llm.openai_compat:make",
            status=_UNVERIFIED,
            hosts=lambda s: [urlsplit(s.base_url).hostname or ""],
        ),
        "gemini": Entry(
            GeminiSettings,
            "hadavin_sdk.llm.gemini:make",
            status=_UNVERIFIED,
            hosts=lambda s: ["generativelanguage.googleapis.com"],
        ),
    },
    "detector": {
        "regex": Entry(RegexSettings, f"{_BUILTIN}:regex_detector"),
        # llm_judge connects through the configured llm kind (its hosts are the llm's).
        "llm_judge": Entry(JudgeSettings, "hadavin_sdk.guard.judge:make", status=_UNVERIFIED),
        "bedrock_guardrail": Entry(
            GuardrailSettings,
            "hadavin_sdk.guard.bedrock_guardrail:make",
            "aws",
            status=_UNVERIFIED,
            # The runtime screens; the control plane reads the guardrail's filters once at start-up.
            hosts=lambda s: [
                f"bedrock-runtime.{s.region}.amazonaws.com",
                f"bedrock.{s.region}.amazonaws.com",
            ],
        ),
    },
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
