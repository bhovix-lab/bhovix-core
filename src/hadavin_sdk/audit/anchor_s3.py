"""Checkpoint anchors in an S3 bucket under Object Lock (`pip install hadavin-sdk[aws]`).

Ported from WARDEN `audit.py` `S3Anchor` (main c78d7709). Edits: the lock mode comes from config (GOVERNANCE by
default, COMPLIANCE only in prod with `retention_ack`), and every put carries `IfNoneMatch="*"`, so an anchor is
never overwritten even before Object Lock applies. The bucket must be written by a principal the runtime cannot
delete with (S11): until the retention ends, a history rewritten afterwards no longer matches its anchors.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

PREFIX = "anchors/"


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
        body = json.dumps({"seq": seq, "hash": head, "signature": signature}, sort_keys=True)
        self._s3.put_object(
            Bucket=self.bucket,
            Key=f"{PREFIX}{seq:012d}.json",
            Body=body.encode("utf-8"),
            ObjectLockMode=self.mode,
            ObjectLockRetainUntilDate=self.clock() + self.retain,
            ChecksumAlgorithm="SHA256",
            IfNoneMatch="*",
        )

    def all(self) -> dict[int, tuple[str, str]]:
        """Every anchor: seq -> (head hash, signature hex)."""
        out: dict[int, tuple[str, str]] = {}
        pages = self._s3.get_paginator("list_objects_v2").paginate(
            Bucket=self.bucket, Prefix=PREFIX
        )
        for page in pages:
            for obj in page.get("Contents") or []:
                raw = self._s3.get_object(Bucket=self.bucket, Key=obj["Key"])["Body"].read()
                a = json.loads(raw)
                out[int(a["seq"])] = (a["hash"], a["signature"])
        return out


def build(settings) -> S3Anchor:
    """From the chain's `anchor:` settings (`kind: s3_object_lock`)."""
    import boto3  # the `aws` extra
    from botocore.config import Config

    # Anchors are written inline every N audit rows: a slow S3 must cost seconds, not botocore's 60 s defaults.
    config = Config(connect_timeout=3, read_timeout=5, retries={"total_max_attempts": 2})
    return S3Anchor(
        settings.bucket,
        boto3.client("s3", region_name=settings.region, config=config),
        mode=settings.mode,
        retain=timedelta(days=settings.retain_days),
    )
