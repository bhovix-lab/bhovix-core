"""Platform secrets: the credentials a backend itself needs (a Slack token, a database DSN, an API key).

Kept apart from the executor's provider (design §4.4): a backend factory gets a ``resolve`` that reads only the
``*_secret_name`` values in its own settings, and no platform name may also be an action's executor secret.
``runtime/``, ``approvals/`` and ``llm/`` never import this module (tests/test_repo_rules.py).
"""

from __future__ import annotations

from collections.abc import Callable, Iterable

from pydantic import BaseModel

from hadavin_sdk.actions.secrets import SecretProvider
from hadavin_sdk.errors import ConfigError


def secret_names(settings: BaseModel) -> set[str]:
    """Every set ``*_secret_name`` value in one backend's settings."""
    return {v for k, v in settings if k.endswith("_secret_name") and v}


def bound(provider: SecretProvider, settings: BaseModel, label: str) -> Callable[[str], str]:
    allowed = secret_names(settings)

    def resolve(name: str) -> str:
        if name not in allowed:
            raise ConfigError(
                f"{label}: may read only the secrets named in its own settings, not {name!r}"
            )
        return provider.get(name)

    return resolve


def check(
    provider: SecretProvider, settings: Iterable[BaseModel], executor_names: set[str]
) -> None:
    """Start-up: platform and executor names never overlap, and every one of them resolves once."""
    platform: set[str] = set().union(*(secret_names(s) for s in settings))
    if overlap := platform & executor_names:
        raise ConfigError(
            f"secret names used by both a backend and an action executor: {sorted(overlap)}; "
            "give the backend its own secret"
        )
    for name in sorted(platform | executor_names):
        # Any provider failure is a start-up failure; the value is never shown.
        try:
            provider.get(name)
        except Exception as exc:
            raise ConfigError(f"secret {name!r} cannot be read at start-up") from exc
