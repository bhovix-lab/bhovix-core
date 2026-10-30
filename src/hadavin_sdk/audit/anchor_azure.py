"""Checkpoint anchors as Azure Blobs under a version-level WORM policy (`pip install hadavin-sdk[azure]`).

The container must have version-level immutability enabled (checked at start-up). Each anchor is uploaded with
`overwrite=False` (If-None-Match: *) and its own time-based immutability policy: `GOVERNANCE` -> `Unlocked`
(a privileged admin can still shorten it), `COMPLIANCE` -> `Locked` (nobody can, until it expires; prod with
`retention_ack` only). Signs in with `DefaultAzureCredential`; the identity writing anchors must not be one
that can delete them (S11).
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

# The extra: a missing install fails at start-up with the hint (backends.make).
from azure.core.exceptions import ResourceExistsError
from azure.identity import DefaultAzureCredential
from azure.storage.blob import BlobImmutabilityPolicyMode, ContainerClient, ImmutabilityPolicy

from hadavin_sdk.audit import anchors
from hadavin_sdk.errors import ConfigError

_MODES = {
    "GOVERNANCE": BlobImmutabilityPolicyMode.UNLOCKED,
    "COMPLIANCE": BlobImmutabilityPolicyMode.LOCKED,
}


class AzureBlobAnchor:
    def __init__(
        self,
        container: Any,
        *,
        mode: str = "GOVERNANCE",
        retain: timedelta = timedelta(days=1),
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._container, self.mode, self.retain = container, mode, retain
        self.clock = clock or (lambda: datetime.now(UTC))

    def put(self, seq: int, head: str, signature: str) -> None:
        name, data = anchors.key(seq), anchors.body(seq, head, signature)
        policy = ImmutabilityPolicy(
            expiry_time=self.clock() + self.retain, policy_mode=_MODES[self.mode]
        )
        try:
            self._container.upload_blob(name, data, overwrite=False, immutability_policy=policy)
        except ResourceExistsError:
            existing = self._container.download_blob(name).readall()
            anchors.already_there(existing, data, seq)

    def all(self) -> dict[int, tuple[str, str]]:
        out: dict[int, tuple[str, str]] = {}
        for item in self._container.list_blobs(name_starts_with=anchors.PREFIX):
            seq, pair = anchors.parse(self._container.download_blob(item.name).readall())
            out[seq] = pair
        return out


def build(settings, deps) -> AzureBlobAnchor:
    """`backends.anchor: {kind: azure_immutable_blob, ...}`."""
    container = ContainerClient(
        settings.account_url,
        settings.container,
        credential=DefaultAzureCredential(),
        connection_timeout=3,  # anchors are written inline: seconds, not the SDK defaults
        read_timeout=5,
        retry_total=2,
    )
    return probed(container, settings)


def probed(container: Any, settings) -> AzureBlobAnchor:
    try:
        props = container.get_container_properties()
    except Exception as exc:  # noqa: BLE001 - any SDK or network error: a start-up ConfigError
        raise ConfigError(
            f"audit anchor azure_immutable_blob: cannot read the container ({type(exc).__name__})"
        ) from None
    if not getattr(props, "immutable_storage_with_versioning_enabled", False):
        raise ConfigError(
            "audit anchor azure_immutable_blob: the container needs version-level immutability enabled"
        )
    return AzureBlobAnchor(
        container, mode=settings.mode, retain=timedelta(days=settings.retain_days)
    )
