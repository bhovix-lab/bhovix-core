"""The base-package kinds, each built through the backend table (`make`), as `app.build` does."""

import hashlib
import json
from decimal import Decimal

from hadavin_sdk.actions.secrets import FakeSecretProvider
from hadavin_sdk.backends import make
from hadavin_sdk.backends.table import (
    FakeChannelSettings,
    FakeLLMSettings,
    KindSettings,
    LocalDirSettings,
    RegexSettings,
)
from hadavin_sdk.config import Route
from tests.contracts.kinds import kind

ROUTES = {
    "default": Route(
        model_id="contract.model-1:1",  # pinned by every kind's rule (a dot, a digit, a tag)
        input_usd_per_mtok=Decimal("3.00"),
        output_usd_per_mtok=Decimal("15.00"),
        max_tokens=64,
    )
}
MESSAGES = [{"role": "user", "content": "Say hello."}]


@kind("store", "memory")
def memory(tmp_path):
    return make("store", KindSettings(kind="memory"))


@kind("audit", "local_dir")
def local_dir(tmp_path):
    return make("audit", LocalDirSettings(kind="local_dir", dir=tmp_path / "audit"))


@kind("secrets", "fake")
def fake_secrets(tmp_path, seed):
    # The configured `fake` kind is empty by design (secrets never live in config); seeding is test-only.
    return FakeSecretProvider(seed)


@kind("llm", "fake")
def fake_llm(tmp_path):
    """Returns the llm and one call it can answer."""
    digest = hashlib.sha256(json.dumps(MESSAGES, sort_keys=True).encode("utf-8")).hexdigest()
    (tmp_path / f"{digest}-1.json").write_text(
        json.dumps({"text": "hello", "input_tokens": 5, "output_tokens": 1}), encoding="utf-8"
    )
    llm = make("llm", FakeLLMSettings(kind="fake", recorded_dir=tmp_path), routes=ROUTES)
    return llm, {"messages": MESSAGES, "system": "Be brief.", "route": "default"}


@kind("detector", "regex")
def regex(tmp_path):
    return make("detector", RegexSettings(kind="regex", threshold=0.5))


@kind("channel", "fake")
def fake_channel(tmp_path, signing_secret):
    settings = FakeChannelSettings(kind="fake", signing_secret_name="sig")  # noqa: S106 - a name
    return make("channel", settings, FakeSecretProvider({"sig": signing_secret}))
