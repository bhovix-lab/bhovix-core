"""Contract suites: every check runs against every registered kind of its capability (design §6, §12.6)."""

import importlib
import inspect
import pkgutil

import pytest

from tests.contracts import kinds
from tests.contracts.kinds import KINDS

for _m in pkgutil.iter_modules(kinds.__path__):
    importlib.import_module(f"{kinds.__name__}.{_m.name}")


def _kinds(capability):
    return pytest.fixture(params=sorted(KINDS[capability]))


def _built(request, made):
    """A kind function may return its backend, or yield it and clean up after the test."""
    if not inspect.isgenerator(made):
        return made
    value = next(made)
    request.addfinalizer(lambda: next(made, None))
    return value


@_kinds("store")
def store(request, tmp_path):
    return _built(request, KINDS["store"][request.param](tmp_path))


@_kinds("audit")
def audit(request, tmp_path):
    return _built(request, KINDS["audit"][request.param](tmp_path))


@_kinds("secrets")
def secrets_factory(request, tmp_path):
    return lambda seed: KINDS["secrets"][request.param](tmp_path, seed)


@_kinds("llm")
def llm_and_call(request, tmp_path):
    return KINDS["llm"][request.param](tmp_path)


@_kinds("llm_wire")
def wire(request, tmp_path):
    """A network llm kind against its fixtures (P5; `fake` has no network, so it is not one)."""
    harness = KINDS["llm_wire"][request.param](tmp_path)
    yield harness
    harness.close()


@_kinds("detector")
def detector(request, tmp_path):
    return KINDS["detector"][request.param](tmp_path)


@_kinds("channel")
def channel_factory(request, tmp_path):
    return lambda secret: KINDS["channel"][request.param](tmp_path, secret)
