"""RDS IAM sign-in for the postgres store (`iam_auth: true`; `pip install hadavin-sdk[aws]`).

The only place the store touches an AWS SDK: a 15-minute IAM token stands in for the password, so no database
password exists anywhere and the task role's `rds-db:connect` decides. Ported from WARDEN `audit.py:_pg_connect`
(main a1e76cbf).
"""

from __future__ import annotations

from collections.abc import Callable

import boto3  # the extra: a missing install is turned into the install hint by store.postgres


def rds_iam(region: str | None) -> Callable[[str, int, str], str]:
    client = boto3.client("rds", region_name=region)

    def password(host: str, port: int, user: str) -> str:
        return client.generate_db_auth_token(DBHostname=host, Port=port, DBUsername=user)

    return password
