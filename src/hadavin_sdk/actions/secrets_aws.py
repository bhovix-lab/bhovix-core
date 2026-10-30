"""`aws_secrets_manager` secrets (`pip install hadavin-sdk[aws]`).

Rewritten, not ported: WARDEN `settings.py` loads secrets into `os.environ`, which would hand every secret to
every module. Here a value is returned to the one caller that asked (the executor, or a backend through its
bound platform resolver). Cache, single-flight and logging rules: `secrets_cache.CachedSecrets`.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

import boto3  # the extra: a missing install fails at start-up with the hint (backends.make)

from hadavin_sdk.actions.secrets_cache import CachedSecrets
from hadavin_sdk.errors import ConfigError


class SecretsManagerProvider(CachedSecrets):
    def __init__(
        self, client: Any, ttl_s: float = 300, clock: Callable[[], float] = time.monotonic
    ) -> None:
        super().__init__(ttl_s, clock)
        self._client = client

    def _fetch(self, name: str) -> str:
        try:
            out = self._client.get_secret_value(SecretId=name)
        except Exception as exc:
            code = getattr(exc, "response", {}).get("Error", {}).get("Code")
            if code == "ResourceNotFoundException":
                raise ConfigError(f"secret {name!r} not found in Secrets Manager") from None
            raise
        if "SecretString" not in out:
            # ponytail: text secrets only; a binary secret needs a decode rule nobody has asked for yet.
            raise ConfigError(f"secret {name!r} is binary; store it as a string")
        return out["SecretString"]


def build(settings, deps) -> SecretsManagerProvider:
    client = boto3.client("secretsmanager", region_name=settings.region)
    return SecretsManagerProvider(client, settings.ttl_s)
