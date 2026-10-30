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


class JudgeSettings(KindSettings):
    route: str  # a key of `routes`; checked against them at load
    threshold: float = Field(default=0.7, ge=0.0, le=1.0)


class GuardrailSettings(KindSettings):
    guardrail_id: str
    guardrail_version: str
    region: str = Field(pattern=_NAME)
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


class EnvSecretsSettings(KindSettings):
    prefix: str = Field(default="HADAVIN_SECRET_", min_length=1)


class AwsSecretsManagerSettings(KindSettings):
    region: str
    ttl_s: float = Field(default=300, ge=0)  # 0 = no cache


class _AnchorSettings(KindSettings):
    """Every anchor kind: COMPLIANCE only in prod with `retention_ack` (the client agreed retention in
    writing); prod also needs the ack for GOVERNANCE (config.py, environment table)."""

    mode: Literal["GOVERNANCE", "COMPLIANCE"] = "GOVERNANCE"
    retain_days: int = Field(default=1, ge=1)
    retention_ack: bool = False


class S3ObjectLockSettings(_AnchorSettings):
    """AWS S3, or any S3-compatible store with Object Lock (MinIO, Ceph RGW) through `endpoint_url`."""

    kind: Literal["s3_object_lock"]
    bucket: str
    region: str
    endpoint_url: str | None = None  # https; plain http only to this machine (a local MinIO)

    @model_validator(mode="after")
    def _endpoint(self) -> S3ObjectLockSettings:
        if self.endpoint_url is not None:
            url = urlsplit(self.endpoint_url)
            local = url.scheme == "http" and url.hostname in _LOOPBACK
            if url.scheme != "https" and not local:
                raise ValueError("endpoint_url must be https (plain http only to this machine)")
        return self


class AzureImmutableBlobSettings(_AnchorSettings):
    """GOVERNANCE -> an Unlocked blob immutability policy, COMPLIANCE -> Locked."""

    kind: Literal["azure_immutable_blob"]
    account_url: str = Field(pattern=r"^https://")  # e.g. https://<account>.blob.core.windows.net
    container: str = Field(pattern=r"^[a-z0-9-]{3,63}$")


class GcsRetentionLockSettings(_AnchorSettings):
    """GOVERNANCE -> the bucket's retention policy, COMPLIANCE -> that policy locked."""

    kind: Literal["gcs_retention_lock"]
    bucket: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{1,220}[a-z0-9]$")


class ChainSettings(KindSettings):
    checkpoint_every: int = Field(default=100, ge=1)


class Ed25519LocalSettings(KindSettings):
    """The PEM key from a file (dev, pilot) or from the secrets kind (`private_key_secret_name`; prod allows
    only this, and only with a WORM anchor: config.py, environment table)."""

    private_key_path: Path | None = None
    private_key_secret_name: str | None = None
    passphrase_secret_name: str | None = None

    @model_validator(mode="after")
    def _one_source(self) -> Ed25519LocalSettings:
        if (self.private_key_path is None) == (self.private_key_secret_name is None):
            raise ValueError("set exactly one of private_key_path and private_key_secret_name")
        return self


class AwsKmsSettings(KindSettings):
    key_id: str
    region: str


class AzureKeyVaultKeySettings(KindSettings):
    # One key version: https://<vault>.vault.azure.net/keys/<name>/<version> (or a managedhsm.azure.net URL).
    key_id: str = Field(pattern=r"^https://[^/]+/keys/[A-Za-z0-9-]+/[A-Za-z0-9]+$")


class GcpKmsSettings(KindSettings):
    key_version: str = Field(
        pattern=r"^projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+/cryptoKeyVersions/[0-9]+$"
    )


_TTL = Field(default=300, ge=0)  # seconds a secret value is cached; 0 = no cache


_PATH = r"^[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*$"


class _VaultConnection(KindSettings):
    """How to reach and sign in to Vault or OpenBao (the `vault` secrets kind and the `vault_transit`
    signer)."""

    address: str  # https; plain http only to this machine (a dev server)
    auth: Literal["token", "approle", "kubernetes"] = "token"
    namespace: str | None = None
    token_env: str = "VAULT_TOKEN"  # noqa: S105 - auth token: the variable name
    role_id: str | None = None  # auth: approle (an identifier, not a secret)
    secret_id_env: str = "VAULT_SECRET_ID"  # noqa: S105 - auth approle: the variable name
    role: str | None = None  # auth: kubernetes
    jwt_path: Path = Path("/var/run/secrets/kubernetes.io/serviceaccount/token")  # auth: kubernetes
    # Default: the auth name. Nested mounts (e.g. team-a/kubernetes) are allowed.
    auth_mount: str | None = Field(default=None, pattern=_PATH)
    ca_cert: Path | None = None
    timeout_s: float = Field(default=10.0, gt=0)

    def _paths(self) -> list[str]:
        return [self.auth_mount or ""]

    @model_validator(mode="after")
    def _checks(self) -> _VaultConnection:
        url = urlsplit(self.address)
        if url.scheme != "https" and not (url.scheme == "http" and url.hostname in _LOOPBACK):
            raise ValueError("address must be https (plain http only to this machine)")
        if {".", ".."} & {seg for p in self._paths() for seg in p.split("/")}:
            raise ValueError("mount, path_prefix and auth_mount may not hold '.' or '..' segments")
        need = {"token": [], "approle": ["role_id"], "kubernetes": ["role"]}[self.auth]
        if missing := [n for n in need if not getattr(self, n)]:
            raise ValueError(f"auth {self.auth} needs: {', '.join(missing)}")
        return self


class VaultSettings(_VaultConnection):
    mount: str = Field(default="secret", pattern=_PATH)
    path_prefix: str = Field(default="", pattern=r"^([A-Za-z0-9_.-]+/)*$")  # e.g. "hadavin/acme/"
    field: str = "value"
    ttl_s: float = _TTL

    def _paths(self) -> list[str]:
        return [self.auth_mount or "", self.mount, self.path_prefix]


class VaultTransitSettings(_VaultConnection):
    """An `ed25519` Transit key, pinned to one version: checkpoints signed before a rotation must still
    verify with the key that signed them."""

    transit_mount: str = Field(default="transit", pattern=_PATH)
    key_name: str = Field(pattern=r"^[A-Za-z0-9_.-]+$")
    key_version: int = Field(ge=1)

    def _paths(self) -> list[str]:
        return [self.auth_mount or "", self.transit_mount, self.key_name]


class AzureKeyVaultSettings(KindSettings):
    vault_url: str = Field(pattern=r"^https://")  # e.g. https://<vault-name>.vault.azure.net
    ttl_s: float = _TTL


class GcpSecretManagerSettings(KindSettings):
    project_id: str = Field(pattern=_NAME)
    ttl_s: float = _TTL


class MountedFileSettings(KindSettings):
    dir: Path
    ttl_s: float = _TTL


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
_AUDIT = "hadavin_sdk.audit"
_SIGNER = "hadavin_sdk.audit.signer"
_ACTIONS = "hadavin_sdk.actions"

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
        "vault": Entry(VaultSettings, f"{_ACTIONS}.secrets_vault:build", status=_UNVERIFIED),
        "azure_key_vault": Entry(
            AzureKeyVaultSettings,
            f"{_ACTIONS}.secrets_azure:build",
            extra="azure",
            status=_UNVERIFIED,
        ),
        "gcp_secret_manager": Entry(
            GcpSecretManagerSettings,
            f"{_ACTIONS}.secrets_gcp:build",
            extra="gcp",
            status=_UNVERIFIED,
        ),
        "mounted_file": Entry(
            MountedFileSettings, f"{_ACTIONS}.secrets_file:build", status=_UNVERIFIED
        ),
    },
    "signer": {
        "none": Entry(KindSettings, f"{_BUILTIN}:no_signer"),
        "ed25519_local": Entry(
            Ed25519LocalSettings, f"{_SIGNER}:build_local", extra="signer", status=_UNVERIFIED
        ),
        "aws_kms": Entry(AwsKmsSettings, f"{_SIGNER}_aws:build", extra="aws", status=_UNVERIFIED),
        "azure_key_vault_key": Entry(
            AzureKeyVaultKeySettings, f"{_SIGNER}_azure:build", extra="azure", status=_UNVERIFIED
        ),
        "gcp_kms": Entry(GcpKmsSettings, f"{_SIGNER}_gcp:build", extra="gcp", status=_UNVERIFIED),
        "vault_transit": Entry(
            VaultTransitSettings, f"{_SIGNER}_vault:build", extra="signer", status=_UNVERIFIED
        ),
    },
    # Where each signed checkpoint is also written, out of the runtime's reach (WORM).
    "anchor": {
        "none": Entry(KindSettings, f"{_BUILTIN}:no_anchor"),
        "s3_object_lock": Entry(
            S3ObjectLockSettings, f"{_AUDIT}.anchor_s3:build", extra="aws", status=_UNVERIFIED
        ),
        "azure_immutable_blob": Entry(
            AzureImmutableBlobSettings,
            f"{_AUDIT}.anchor_azure:build",
            extra="azure",
            status=_UNVERIFIED,
        ),
        "gcs_retention_lock": Entry(
            GcsRetentionLockSettings, f"{_AUDIT}.anchor_gcs:build", extra="gcp", status=_UNVERIFIED
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
            ChainSettings, "hadavin_sdk.audit.chain:build", extra="signer", status=_UNVERIFIED
        ),
    },
    "llm": {
        "fake": Entry(FakeLLMSettings, f"{_BUILTIN}:fake_llm"),
        # Every kind below is slice2-unverified until its P9 live run (design 12.1).
        "anthropic": Entry(AnthropicSettings, "hadavin_sdk.llm.anthropic:make", "anthropic"),
        "bedrock": Entry(BedrockSettings, "hadavin_sdk.llm.bedrock:make", "aws"),
        "openai_compat": Entry(OpenAICompatSettings, "hadavin_sdk.llm.openai_compat:make"),
        "gemini": Entry(GeminiSettings, "hadavin_sdk.llm.gemini:make"),
    },
    "detector": {
        "regex": Entry(RegexSettings, f"{_BUILTIN}:regex_detector"),
        # slice2-unverified until the P9 live run (design 12.1).
        "llm_judge": Entry(JudgeSettings, "hadavin_sdk.guard.judge:make"),
        "bedrock_guardrail": Entry(
            GuardrailSettings, "hadavin_sdk.guard.bedrock_guardrail:make", "aws"
        ),
    },
    "channel": {"fake": Entry(FakeChannelSettings, f"{_BUILTIN}:fake_channel")},
}

# The Deps fields a factory of each capability may see (besides its own bound `resolve`).
ALLOWED: dict[str, frozenset[str]] = {
    "secrets": frozenset(),
    "signer": frozenset(),
    "anchor": frozenset(),
    "store": frozenset(),
    "audit": frozenset({"store", "signer", "anchor"}),
    "llm": frozenset({"routes"}),
    "detector": frozenset({"llm"}),
    "channel": frozenset({"store"}),
}

# Capabilities a config may leave out, and the kind they get.
DEFAULTS: dict[str, str] = {
    "secrets": "fake",
    "signer": "none",
    "anchor": "none",
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
NOT_PROD: frozenset[tuple[str, str]] = frozenset({("signer", "none"), ("anchor", "none")})
