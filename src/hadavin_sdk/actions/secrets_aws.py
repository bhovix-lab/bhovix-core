"""`aws_secrets_manager` secrets (`pip install hadavin-sdk[aws]`).

Rewritten, not ported: WARDEN `settings.py` loads secrets into `os.environ`, which would hand every secret to
every module. Here a value is returned to the one caller that asked (the executor, or a backend through its
bound platform resolver) and cached for `ttl_s` seconds (0 = no cache), so a rotated value is picked up
within one TTL. Values are never logged; errors name the secret and the error class only.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from typing import Any

from hadavin_sdk.errors import ConfigError


class SecretsManagerProvider:
    def __init__(
        self, client: Any, ttl_s: float = 300, clock: Callable[[], float] = time.monotonic
    ) -> None:
        self._client, self.ttl_s, self._clock = client, ttl_s, clock
        self._cache: dict[str, tuple[float, str]] = {}
        self._lock = threading.Lock()

    def get(self, name: str) -> str:
        now = self._clock()
        with self._lock:
            hit = self._cache.get(name)
        if hit is not None and now < hit[0]:
            return hit[1]
        value = self._fetch(name)
        if self.ttl_s > 0:
            with self._lock:
                self._cache[name] = (now + self.ttl_s, value)
        return value

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
    import boto3  # the `aws` extra

    client = boto3.client("secretsmanager", region_name=settings.region)
    return SecretsManagerProvider(client, settings.ttl_s)
