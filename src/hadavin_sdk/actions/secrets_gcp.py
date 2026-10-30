"""`gcp_secret_manager` secrets (`pip install hadavin-sdk[gcp]`).

Signs in with Application Default Credentials: the attached service account or workload identity in GCP,
`gcloud auth application-default login` on a laptop; no key file lives in config. Reads the `latest` version.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from typing import Any

# The extra: a missing install fails at start-up with the hint (backends.make).
from google.api_core.exceptions import NotFound
from google.auth.exceptions import DefaultCredentialsError
from google.cloud import secretmanager

from hadavin_sdk.actions.secrets_cache import CachedSecrets
from hadavin_sdk.errors import ConfigError

_NAME = re.compile(r"[A-Za-z0-9_-]{1,255}")


class GcpSecretManagerProvider(CachedSecrets):
    def __init__(
        self,
        client: Any,
        project_id: str,
        ttl_s: float = 300,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        super().__init__(ttl_s, clock)
        self._client, self.project_id = client, project_id

    def _fetch(self, name: str) -> str:
        if not _NAME.fullmatch(name):  # the name becomes part of a resource path
            raise ConfigError(f"secret {name!r}: GCP names are letters, digits, '_' and '-'")
        path = f"projects/{self.project_id}/secrets/{name}/versions/latest"
        try:
            # Bounded: a fetch holds the provider's lock (the SDK default is 60 s plus a 60 s retry deadline).
            data = self._client.access_secret_version(name=path, retry=None, timeout=5).payload.data
        except NotFound:
            raise ConfigError(f"secret {name!r} not found in GCP Secret Manager") from None
        return data.decode("utf-8")


def build(settings, deps) -> GcpSecretManagerProvider:
    try:
        client = secretmanager.SecretManagerServiceClient()
    except DefaultCredentialsError:
        raise ConfigError(
            "secrets gcp_secret_manager: no Application Default Credentials "
            "(attach a service account, or run gcloud auth application-default login)"
        ) from None
    return GcpSecretManagerProvider(client, settings.project_id, settings.ttl_s)
