"""Pluggable backends: one table (``table.py``) maps each capability and kind to a settings model and a
factory. ``make`` builds one backend, handing its factory only what that capability may use."""

from __future__ import annotations

import importlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from hadavin_sdk.actions.secrets import FakeSecretProvider, SecretProvider
from hadavin_sdk.backends.platform_secrets import bound
from hadavin_sdk.backends.table import ALLOWED, TABLE, KindSettings
from hadavin_sdk.errors import ConfigError


@dataclass(frozen=True)
class Deps:
    """What a factory receives besides its settings. Fields its capability may not use stay None."""

    resolve: Callable[[str], str]
    routes: Mapping[str, Any] | None = None
    store: Any = None
    signer: Any = None
    anchor: Any = None
    llm: Any = None


def make(
    capability: str,
    settings: KindSettings,
    provider: SecretProvider | None = None,
    **available: Any,
) -> Any:
    """Build one backend. ``provider`` backs the factory's ``resolve`` (None: nothing to read from)."""
    entry = TABLE[capability][settings.kind]
    module_name, func = entry.factory.split(":")
    try:
        module = importlib.import_module(module_name)
    except ImportError as exc:
        # Only a missing third-party package means "install the extra"; a broken Hadavin module (or an import
        # error inside an installed package) keeps its own message.
        missing = isinstance(exc, ModuleNotFoundError) and exc.name or ""
        if entry.extra is None or not missing or missing.split(".")[0] == "hadavin_sdk":
            raise
        raise ConfigError(
            f"backend {capability} {settings.kind!r} needs: pip install hadavin-sdk[{entry.extra}]"
        ) from exc
    label = f"backend {capability} {settings.kind!r}"
    deps = Deps(
        resolve=bound(provider or FakeSecretProvider({}), settings, label),
        **{k: v for k, v in available.items() if k in ALLOWED[capability]},
    )
    return getattr(module, func)(settings, deps)


__all__ = ["Deps", "make"]
