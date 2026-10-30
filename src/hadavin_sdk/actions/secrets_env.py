"""`env` secrets: read from environment variables (`dev` only, by the environment table).

A name maps to ``<prefix><NAME>``, upper-cased, with every character other than a letter or digit as ``_``
(``fixture-token`` -> ``HADAVIN_SECRET_FIXTURE_TOKEN``). No cache: reading the environment costs nothing.
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping

from hadavin_sdk.errors import ConfigError


class EnvSecretProvider:
    def __init__(self, prefix: str, environ: Mapping[str, str] = os.environ) -> None:
        self.prefix, self._environ = prefix, environ

    def var(self, name: str) -> str:
        return self.prefix + re.sub(r"[^A-Za-z0-9]", "_", name).upper()

    def get(self, name: str) -> str:
        value = self._environ.get(self.var(name))
        if value is None:
            raise ConfigError(f"secret {name!r} not found (environment variable {self.var(name)})")
        return value


def build(settings, deps) -> EnvSecretProvider:
    return EnvSecretProvider(settings.prefix)
