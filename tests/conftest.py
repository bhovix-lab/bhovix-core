"""Shared fixtures: every test works on a copy of the fixture config in tmp_path, never the repo."""

import json
import shutil
from pathlib import Path

import pytest

from bhovix_core.models import GateRun

FIXTURES = Path(__file__).parent / "fixtures"


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
        golden_sha256="0" * 64,
        n=1,
        passed=1 if green else 0,
        pass_rate=1.0 if green else 0.0,
        threshold=1.0,
        green=green,
    )
    (registry.config.root / "qualified.json").write_text(
        json.dumps([run.model_dump(mode="json")]), encoding="utf-8"
    )


@pytest.fixture
def cfg_dir(tmp_path: Path) -> Path:
    return make_cfg(tmp_path)
