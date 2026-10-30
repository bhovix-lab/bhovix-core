"""Checkpoint anchors in an S3 bucket under Object Lock (`pip install hadavin-sdk[aws]`).

Ported from WARDEN `audit.py` `S3Anchor` (main c78d7709). Edits: the lock mode comes from config (GOVERNANCE by
default, COMPLIANCE only in prod with `retention_ack`), and every put carries `IfNoneMatch="*"`, so an anchor is
never overwritten even before Object Lock applies (a 412 with the same bytes is an earlier put whose answer was
lost). The bucket must be written by a principal the runtime cannot delete with (S11): until the retention
ends, a history rewritten afterwards no longer matches its anchors.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

# The extra: a missing install fails at start-up with the hint (backends.make).
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from hadavin_sdk.audit import anchors

PREFIX = anchors.PREFIX


class S3Anchor:
    def __init__(
        self,
        bucket: str,
        client: Any,
        *,
        mode: str = "GOVERNANCE",
        retain: timedelta = timedelta(days=1),
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.bucket, self._s3, self.mode, self.retain = bucket, client, mode, retain
        self.clock = clock or (lambda: datetime.now(UTC))

    def put(self, seq: int, head: str, signature: str) -> None:
        name, data = anchors.key(seq), anchors.body(seq, head, signature)
        try:
            self._s3.put_object(
                Bucket=self.bucket,
                Key=name,
                Body=data,
                ObjectLockMode=self.mode,
                ObjectLockRetainUntilDate=self.clock() + self.retain,
                ChecksumAlgorithm="SHA256",
                IfNoneMatch="*",
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "PreconditionFailed":
                raise
            existing = self._s3.get_object(Bucket=self.bucket, Key=name)["Body"].read()
            anchors.already_there(existing, data, seq)

    def all(self) -> dict[int, tuple[str, str]]:
        """Every anchor: seq -> (head hash, signature hex)."""
        out: dict[int, tuple[str, str]] = {}
        pages = self._s3.get_paginator("list_objects_v2").paginate(
            Bucket=self.bucket, Prefix=PREFIX
        )
        for page in pages:
            for obj in page.get("Contents") or []:
                raw = self._s3.get_object(Bucket=self.bucket, Key=obj["Key"])["Body"].read()
                seq, pair = anchors.parse(raw)
                out[seq] = pair
        return out


def build(settings, deps) -> S3Anchor:
    """`backends.anchor: {kind: s3_object_lock, ...}`; `endpoint_url` for MinIO / Ceph RGW (Object Lock on; the
    store must accept conditional puts (`If-None-Match: *`) and SHA-256 checksums: older Ceph releases do not)."""
    # Anchors are written inline every N audit rows: a slow S3 must cost seconds, not botocore's 60 s defaults.
    config = Config(connect_timeout=3, read_timeout=5, retries={"total_max_attempts": 2})
    client = boto3.client(
        "s3", region_name=settings.region, endpoint_url=settings.endpoint_url, config=config
    )
    return S3Anchor(
        settings.bucket,
        client,
        mode=settings.mode,
        retain=timedelta(days=settings.retain_days),
    )
