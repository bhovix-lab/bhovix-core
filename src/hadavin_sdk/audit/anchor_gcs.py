"""Checkpoint anchors in a Cloud Storage bucket with a retention policy (`pip install hadavin-sdk[gcp]`).

Each anchor is written with `if_generation_match=0` (only if no object of that name exists), and the bucket's
retention policy keeps it from deletion or replacement until it ages out. Checked at start-up: the bucket has a
retention period of at least `retain_days`; `COMPLIANCE` (prod with `retention_ack` only) also needs the policy
**locked**, so nobody can shorten or remove it. Signs in with Application Default Credentials; the identity
writing anchors must not be one that can delete them (S11).
"""

from __future__ import annotations

from typing import Any

# The extra: a missing install fails at start-up with the hint (backends.make).
from google.api_core.exceptions import PreconditionFailed
from google.auth.exceptions import DefaultCredentialsError
from google.cloud import storage

from hadavin_sdk.audit import anchors
from hadavin_sdk.errors import ConfigError


class GcsAnchor:
    def __init__(self, bucket: Any) -> None:
        self._bucket = bucket

    def put(self, seq: int, head: str, signature: str) -> None:
        name, data = anchors.key(seq), anchors.body(seq, head, signature)
        blob = self._bucket.blob(name)
        try:
            blob.upload_from_string(data, content_type="application/json", if_generation_match=0)
        except PreconditionFailed:
            anchors.already_there(self._bucket.blob(name).download_as_bytes(), data, seq)

    def all(self) -> dict[int, tuple[str, str]]:
        out: dict[int, tuple[str, str]] = {}
        for blob in self._bucket.list_blobs(prefix=anchors.PREFIX):
            seq, pair = anchors.parse(blob.download_as_bytes())
            out[seq] = pair
        return out


def build(settings, deps) -> GcsAnchor:
    """`backends.anchor: {kind: gcs_retention_lock, ...}`."""
    try:
        client = storage.Client()
    except DefaultCredentialsError:
        raise ConfigError(
            "audit anchor gcs_retention_lock: no Application Default Credentials"
        ) from None
    return probed(client.bucket(settings.bucket), settings)


def probed(bucket: Any, settings) -> GcsAnchor:
    try:
        bucket.reload()
    except Exception as exc:  # noqa: BLE001 - any SDK or network error: a start-up ConfigError
        raise ConfigError(
            f"audit anchor gcs_retention_lock: cannot read the bucket ({type(exc).__name__})"
        ) from None
    if (bucket.retention_period or 0) < settings.retain_days * 86400:
        raise ConfigError(
            f"audit anchor gcs_retention_lock: the bucket needs a retention policy of at least "
            f"{settings.retain_days} day(s)"
        )
    if settings.mode == "COMPLIANCE" and not bucket.retention_policy_locked:
        raise ConfigError(
            "audit anchor gcs_retention_lock: COMPLIANCE needs a locked retention policy"
        )
    return GcsAnchor(bucket)
