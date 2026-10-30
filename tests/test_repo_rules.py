"""Repository rules: proprietary licence everywhere, and the core never depends on a demo."""

import ast
import subprocess
import tomllib
from pathlib import Path

import yaml

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
            hits += [
                f"{path.name}: {n}" for n in names if n.split(".")[0] in {"demos", "demo", "tests"}
            ]
    return hits


def missing_rollback_tests(root: Path, action_dirs: list[Path]) -> list[str]:
    """Every reversible contract must name a rollback_test that exists (file + test function)."""
    problems = []
    for folder in action_dirs:
        for path in sorted(folder.glob("*.yaml")):
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            if data.get("risk_class") != "reversible":
                continue
            node = data.get("rollback_test") or ""
            file, _, func = node.partition("::")
            target = root / file
            if not func or not target.is_file() or f"def {func}(" not in target.read_text("utf-8"):
                problems.append(f"{path.name}: rollback_test {node!r} not found")
    return problems


def action_dirs(root: Path) -> list[Path]:
    return [root / "tests/fixtures/config/actions", *root.glob("demos/*/config/actions")]


def test_licences_are_proprietary():
    files = tracked_files(ROOT)
    assert {"LICENSE", "pyproject.toml"} <= set(files)
    assert licence_problems(ROOT, files) == []


def test_core_never_imports_demos():
    assert core_imports_demos(ROOT / "src" / "hadavin_sdk") == []


def test_every_reversible_contract_names_an_existing_rollback_test():
    assert missing_rollback_tests(ROOT, action_dirs(ROOT)) == []


SECRET_HOLDERS = {
    "hadavin_sdk.actions.secrets",
    "hadavin_sdk.actions.executor",
    "hadavin_sdk.backends.platform_secrets",  # backends' own secrets (design 4.4)
}


def secret_imports(pkg_dirs: list[Path]) -> list[str]:
    """runtime, approvals and llm must never import the secret provider or the executor."""
    hits = []
    for d in pkg_dirs:
        for path in d.rglob("*.py"):
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                names = []
                if isinstance(node, ast.Import):
                    names = [a.name for a in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module:
                    names = [node.module] + [f"{node.module}.{a.name}" for a in node.names]
                hits += [f"{path.name}: {n}" for n in names if n in SECRET_HOLDERS]
    return hits


def test_import_boundary_runtime_approvals_llm_never_see_secrets():
    core = ROOT / "src" / "hadavin_sdk"
    assert secret_imports([core / "runtime", core / "approvals", core / "llm"]) == []


def test_plant_runtime_importing_executor_is_caught(tmp_path):
    (tmp_path / "bad.py").write_text("from hadavin_sdk.actions import executor\n", encoding="utf-8")
    assert secret_imports([tmp_path]) == ["bad.py: hadavin_sdk.actions.executor"]


def test_plant_runtime_importing_platform_secrets_is_caught(tmp_path):
    (tmp_path / "bad.py").write_text(
        "from hadavin_sdk.backends.platform_secrets import bound\n", encoding="utf-8"
    )
    assert secret_imports([tmp_path]) == ["bad.py: hadavin_sdk.backends.platform_secrets"]


def test_plant_missing_rollback_test_is_caught(tmp_path):
    actions = tmp_path / "actions"
    actions.mkdir()
    (actions / "a.yaml").write_text(
        "risk_class: reversible\nrollback_test: tests/t.py::test_gone\n", encoding="utf-8"
    )
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "t.py").write_text("def test_other():\n    pass\n", encoding="utf-8")
    assert missing_rollback_tests(tmp_path, [actions]) == [
        "a.yaml: rollback_test 'tests/t.py::test_gone' not found"
    ]


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
