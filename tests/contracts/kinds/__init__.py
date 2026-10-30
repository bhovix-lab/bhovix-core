"""Kind fixtures for the contract suites. Each module here registers the kinds it can build with `@kind`;
`tests/contracts/conftest.py` imports every module at collection, so a new kind is one new module."""

from collections import defaultdict
from collections.abc import Callable
from typing import Any

KINDS: dict[str, dict[str, Callable[..., Any]]] = defaultdict(dict)


def kind(capability: str, name: str):
    def register(fn):
        KINDS[capability][name] = fn
        return fn

    return register
