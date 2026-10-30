"""`azure_key_vault` secrets (`pip install hadavin-sdk[azure]`).

Signs in with `DefaultAzureCredential`: a managed identity or workload identity in Azure, the developer's
`az login` on a laptop; no client secret lives in config. Azure secret names allow letters, digits and dashes
only, so name secrets that way (`slack-signing`, not `slack_signing`).
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from typing import Any

# The extra: a missing install fails at start-up with the hint (backends.make).
from azure.core.exceptions import ResourceNotFoundError
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

from hadavin_sdk.actions.secrets_cache import CachedSecrets
from hadavin_sdk.errors import ConfigError

_NAME = re.compile(r"[A-Za-z0-9-]{1,127}")


class AzureKeyVaultProvider(CachedSecrets):
    def __init__(
        self, client: Any, ttl_s: float = 300, clock: Callable[[], float] = time.monotonic
    ) -> None:
        super().__init__(ttl_s, clock)
        self._client = client

    def _fetch(self, name: str) -> str:
        if not _NAME.fullmatch(name):  # the name becomes part of the request path
            raise ConfigError(f"secret {name!r}: Azure names are letters, digits and '-'")
        try:
            return self._client.get_secret(name).value or ""
        except ResourceNotFoundError:
            raise ConfigError(f"secret {name!r} not found in Azure Key Vault") from None


def build(settings, deps) -> AzureKeyVaultProvider:
    # Bounded: a fetch holds the provider's lock, so a stalled Key Vault must cost seconds, not the SDK's
    # 300-second defaults and 10 retries.
    client = SecretClient(
        vault_url=settings.vault_url,
        credential=DefaultAzureCredential(),
        connection_timeout=3,
        read_timeout=5,
        retry_total=2,
    )
    return AzureKeyVaultProvider(client, settings.ttl_s)
