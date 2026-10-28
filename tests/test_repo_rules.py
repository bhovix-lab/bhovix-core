"""Repository rules: proprietary licence everywhere, and the core never depends on a demo."""

import ast
import subprocess
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LICENCE_TEXT = (
    "Copyright (c) 2026 Hadavin. All rights reserved.\n"
    "\n"
    "This source code is proprietary and confidential. No licence is granted to use, copy,\n"
    "modify, distribute or create derivative works of it, except under a separate written\n"
    "agreement with Hadavin. Viewing this repository on GitHub does not grant any such licence.\n"
)


def tracked_files(root: Path) -> list[str]:
    out = subprocess.run(
        ["git", "ls-files"],  # noqa: S607 - git from PATH, fixed argv
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    )
    return out.stdout.splitlines()


def licence_problems(root: Path, files: list[str]) -> list[str]:
    """Every tracked LICENSE and pyproject.toml must be proprietary."""
    problems = []
    for name in files:
        path = root / name
        if path.name == "LICENSE" and path.read_text(encoding="utf-8") != LICENCE_TEXT:
            problems.append(f"{name}: not the proprietary licence text")
        if path.name == "pyproject.toml":
            project = tomllib.loads(path.read_text(encoding="utf-8")).get("project", {})
            if project.get("license") != "LicenseRef-Proprietary":
                problems.append(f"{name}: license is not LicenseRef-Proprietary")
            if project.get("authors") != [{"name": "Hadavin"}]:
                problems.append(f"{name}: authors is not Hadavin")
    return problems


def core_imports_demos(core_dir: Path) -> list[str]:
    """Any import of the demos package from inside the core."""
    hits = []
    for path in core_dir.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            hits += [f"{path.name}: {n}" for n in names if n.split(".")[0] in {"demos", "demo"}]
    return hits


def test_licences_are_proprietary():
    files = tracked_files(ROOT)
    assert {"LICENSE", "pyproject.toml"} <= set(files)
    assert licence_problems(ROOT, files) == []


def test_core_never_imports_demos():
    assert core_imports_demos(ROOT / "src" / "hadavin_sdk") == []


# Plant checks: each guard must catch a planted violation.
def test_plant_apache_licence_is_caught(tmp_path):
    (tmp_path / "LICENSE").write_text("Apache License\nVersion 2.0\n", encoding="utf-8")
    assert licence_problems(tmp_path, ["LICENSE"]) == ["LICENSE: not the proprietary licence text"]


def test_plant_open_pyproject_is_caught(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "x"\nlicense = "Apache-2.0"\nauthors = [{ name = "Someone" }]\n',
        encoding="utf-8",
    )
    assert len(licence_problems(tmp_path, ["pyproject.toml"])) == 2


def test_plant_core_importing_a_demo_is_caught(tmp_path):
    (tmp_path / "bad.py").write_text("from demos.invoice_po import app\n", encoding="utf-8")
    assert core_imports_demos(tmp_path) == ["bad.py: demos.invoice_po"]
