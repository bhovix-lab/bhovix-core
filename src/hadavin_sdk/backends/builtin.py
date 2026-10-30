"""Factories for the kinds that ship in the base package (no extra needed). Each is ``(settings, deps)``."""

from __future__ import annotations

from hadavin_sdk.actions.secrets import FakeSecretProvider
from hadavin_sdk.approvals.channel import FakeChannel
from hadavin_sdk.audit.local_dir import LocalDirSink
from hadavin_sdk.guard.injection import RegexDetector
from hadavin_sdk.llm.fake import FakeLLM
from hadavin_sdk.store.memory import MemoryStore


def fake_secrets(settings, deps) -> FakeSecretProvider:
    # Empty on purpose: secrets never live in config. Tests pass their own provider to app.build(secrets=).
    return FakeSecretProvider({})


def no_signer(settings, deps) -> None:
    # The default: no checkpoints (`local_dir` needs none; `chain` then keeps an unsigned chain).
    return None


def no_anchor(settings, deps) -> None:
    # The default: checkpoints stay only in the store (refused in prod by the environment table).
    return None


def memory_store(settings, deps) -> MemoryStore:
    return MemoryStore()


def local_dir_audit(settings, deps) -> LocalDirSink:
    return LocalDirSink(settings.dir)


def fake_llm(settings, deps) -> FakeLLM:
    return FakeLLM(settings.recorded_dir, dict(deps.routes))


def regex_detector(settings, deps) -> RegexDetector:
    return RegexDetector(settings.threshold)


def fake_channel(settings, deps) -> FakeChannel:
    name = settings.signing_secret_name
    return FakeChannel(deps.resolve(name) if name else "")
