"""Shared fixtures: every test works on a copy of the fixture config in tmp_path, never the repo."""

import shutil
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


def make_cfg(tmp_path: Path, port: int = 0) -> Path:
    for name in ("config", "recorded", "inputs", "golden"):
        shutil.copytree(FIXTURES / name, tmp_path / name)
    cfg = tmp_path / "config" / "config.yaml"
    cfg.write_text(cfg.read_text(encoding="utf-8").replace("{port}", str(port)), encoding="utf-8")
    return tmp_path / "config"


@pytest.fixture
def cfg_dir(tmp_path: Path) -> Path:
    return make_cfg(tmp_path)
