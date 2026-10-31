"""Shared fixtures: every test works on a copy of the fixture config in tmp_path, never the repo."""

import os
import secrets
import shutil
from pathlib import Path

import pytest

from hadavin_sdk.models import GateRun

FIXTURES = Path(__file__).parent / "fixtures"

# Tests never reach a real AWS account: no profile, config or credential_process from the machine running
# them, only fake keys (moto and the in-process stubs answer every call). Set before any boto3 session exists.
# Nor to any other cloud or a redirected endpoint: endpoint overrides, container and web-identity credentials,
# and the Google and Azure credential variables of the machine running them.
_ISOLATED = (
    "AWS_PROFILE",
    "AWS_DEFAULT_PROFILE",
    "AWS_SESSION_TOKEN",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
)
_ISOLATED_PREFIXES = (
    "AWS_ENDPOINT_URL",
    "AWS_CONTAINER_CREDENTIALS_",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "AZURE_",
)
for _name in [n for n in os.environ if n in _ISOLATED or n.startswith(_ISOLATED_PREFIXES)]:
    os.environ.pop(_name, None)
os.environ["AWS_CONFIG_FILE"] = os.devnull
os.environ["AWS_SHARED_CREDENTIALS_FILE"] = os.devnull
os.environ["AWS_ACCESS_KEY_ID"] = "AKIA" + "IOSFODNN7EXAMPLE"
os.environ["AWS_SECRET_ACCESS_KEY"] = "fake" + "-secret-key"
os.environ["AWS_EC2_METADATA_DISABLED"] = "true"


def make_cfg(tmp_path: Path, port: int = 0) -> Path:
    for name in ("config", "recorded", "inputs", "golden"):
        shutil.copytree(FIXTURES / name, tmp_path / name, dirs_exist_ok=True)
    cfg = tmp_path / "config" / "config.yaml"
    cfg.write_text(cfg.read_text(encoding="utf-8").replace("{port}", str(port)), encoding="utf-8")
    return tmp_path / "config"


def qualify(registry, agent_id: str = "test-agent", green: bool = True) -> None:
    """Write a gate run for the agent's current model, prompt and config (tests before S8's evals gate)."""
    agent = registry.agents[agent_id]
    run = GateRun(
        agent_id=agent_id,
        model_id=registry.config.routes[agent.model_route].model_id,
        prompt_sha256=registry.prompt_sha256(agent_id),
        config_hash=registry.config_hash(agent_id),
        golden_sha256=registry.golden_sha256(agent_id),
        n=1,
        passed=1 if green else 0,
        pass_rate=1.0 if green else 0.0,
        threshold=1.0,
        green=green,
    )
    (registry.config.root / "qualified.jsonl").write_text(
        run.model_dump_json() + "\n", encoding="utf-8"
    )


@pytest.fixture
def cfg_dir(tmp_path: Path) -> Path:
    return make_cfg(tmp_path)


@pytest.fixture
def fake_system():
    """fixture-records on a random port with a random token (shared with the fake secret provider)."""
    from tests.fixtures.fake_system import FakeSystem

    system = FakeSystem(token=secrets.token_hex(16)).start()
    yield system
    system.stop()


@pytest.fixture
def live_cfg_dir(tmp_path: Path, fake_system) -> Path:
    return make_cfg(tmp_path, port=fake_system.port)
