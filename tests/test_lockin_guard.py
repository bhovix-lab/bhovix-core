"""CI lock-in guard (owner rule 2026-10-31, "no single dependency"; spec: single-dependency audit §3a-3c).

Three rules, each with plant tests that prove it fails on a planted violation:
  a. a vendor SDK is imported only inside its own kind module; open-source libraries stay in their layer;
  b. every capability has a neutral prod kind and at least two prod kinds, or a dated EXCEPTIONS entry;
  c. no vendor identifiers (names, regions, hosts, model ids, account ids) in core logic.
Known violations go in dated lists. A stale entry (its violation is gone) fails the test, and so does an
overdue one, so an entry cannot linger.
"""

import ast
import re
import sys
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path

from hadavin_sdk.backends.table import DEV_ONLY, NOT_PROD, TABLE

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
PKG = "hadavin_sdk"
TODAY = datetime.now(UTC).date()  # expiry checks fail after a review_by date, by design


@dataclass(frozen=True)
class Pending:
    """A known violation with a scheduled fix."""

    reason: str
    fix_ref: str
    decided: date
    review_by: date  # the test fails after this date


# ---------------------------------------------------------------------------------------------- rule a

BASE_OK = {"pydantic", "pydantic_settings", "yaml"}  # base dependencies, allowed anywhere
_AWS = {
    f"{PKG}.llm.bedrock",
    f"{PKG}.actions.secrets_aws",
    f"{PKG}.audit.anchor_s3",
    f"{PKG}.audit.signer_aws",
    f"{PKG}.guard.bedrock_guardrail",
    f"{PKG}.store.auth_aws",
}
_GCP = {
    f"{PKG}.llm.anthropic",  # Vertex token errors (google-auth)
    f"{PKG}.actions.secrets_gcp",
    f"{PKG}.audit.anchor_gcs",
    f"{PKG}.audit.signer_gcp",
}
_AZURE = {
    f"{PKG}.actions.secrets_azure",
    f"{PKG}.audit.anchor_azure",
    f"{PKG}.audit.signer_azure",
}
VENDOR_IMPORTS: dict[str, set[str]] = {
    "boto3": _AWS,
    "botocore": _AWS,  # the same set object
    "anthropic": {f"{PKG}.llm.anthropic"},
    "google": _GCP,
    "azure": _AZURE,
    # added with their kinds: hvac, slack_sdk, kubernetes, opentelemetry
}
LIBRARY_IMPORTS: dict[str, set[str]] = {  # open-source libraries kept in their layer
    "psycopg": {f"{PKG}.store.postgres", f"{PKG}.store.migrate"},
    "cryptography": {
        f"{PKG}.audit.signer",
        f"{PKG}.audit.signer_aws",
        f"{PKG}.audit.signer_gcp",
    },
    "markdown_it": {f"{PKG}.approvals.gate"},
    # added later: fastapi, authlib, webauthn (portal_api only)
}
# (top-level import, module) -> scheduled fix. Empty on main: P3b moved every vendor import into its kind.
PENDING: dict[tuple[str, str], Pending] = {}
DYNAMIC_IMPORT_OK = {
    f"{PKG}.backends",
    f"{PKG}.actions.executor",
}  # table factories; contract hooks
# Vendor modules that are helpers of a kind, not TABLE factories themselves.
VENDOR_HELPERS = {f"{PKG}.store.auth_aws"}


def module_name(src: Path, path: Path) -> str:
    parts = list(path.relative_to(src).with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _dynamic_target(node: ast.Call) -> tuple[bool, str | None]:
    """Is this a call to import_module / __import__, and with which constant name."""
    f = node.func
    name = f.attr if isinstance(f, ast.Attribute) else f.id if isinstance(f, ast.Name) else ""
    if name not in {"import_module", "__import__"}:
        return False, None
    arg = node.args[0] if node.args else None
    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
        return True, arg.value
    return True, None


def import_problems(
    src: Path,
    vendor: dict[str, set[str]],
    library: dict[str, set[str]],
    pending: dict[tuple[str, str], Pending],
    dynamic_ok: set[str],
    today: date,
) -> list[str]:
    out: list[str] = []
    seen: set[tuple[str, str]] = set()
    for path in sorted(src.rglob("*.py")):
        mod = module_name(src, path)
        found: list[str] = []
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Import):
                found += [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    out.append(f"{mod}: relative import (use an absolute one)")
                elif node.module:
                    found.append(node.module)
            elif isinstance(node, ast.Call):
                dynamic, const = _dynamic_target(node)
                if dynamic and mod not in dynamic_ok:
                    out.append(f"{mod}: dynamic import outside DYNAMIC_IMPORT_OK")
                if const:
                    found.append(const)
        for name in found:
            top = name.split(".")[0]
            seen.add((top, mod))
            if top == "importlib" and mod not in dynamic_ok:
                out.append(f"{mod}: imports importlib (aliased dynamic imports hide from the scan)")
            allowed = (
                top in sys.stdlib_module_names
                or top == PKG
                or top in BASE_OK
                or mod in vendor.get(top, set())
                or mod in library.get(top, set())
                or (top, mod) in pending
            )
            if not allowed:
                where = (
                    "vendor SDK" if top in vendor else "library" if top in library else "unknown"
                )
                out.append(f"{mod}: imports {top} ({where}) outside its allowed modules")
    for key, p in pending.items():
        if key not in seen:
            out.append(f"PENDING {key} is fixed: delete the entry")
        if p.review_by < today:
            out.append(
                f"PENDING {key} is overdue ({p.review_by}): fix it or re-decide with a new date"
            )
    return out


def factory_modules() -> set[str]:
    return {e.factory.split(":")[0] for kinds in TABLE.values() for e in kinds.values()}


def vendor_module_problems(
    src: Path, vendor: dict[str, set[str]], factories: set[str], helpers: set[str]
) -> list[str]:
    """Every vendor module that exists is a kind (a TABLE factory module) or a declared helper of one."""
    out = []
    for mod in sorted(set().union(*vendor.values())):
        rel = Path(*mod.split("."))
        if (
            not (src / rel.with_suffix(".py")).is_file()
            and not (src / rel / "__init__.py").is_file()
        ):
            continue  # named ahead of time: skipped until it exists
        if mod not in factories | helpers:
            out.append(
                f"{mod}: imports a vendor SDK but is neither a TABLE kind nor a VENDOR_HELPER"
            )
    for mod in helpers:
        if mod not in set().union(*vendor.values()):
            out.append(f"VENDOR_HELPERS {mod} is not a vendor module: delete the entry")
    return out


def test_vendor_sdks_stay_inside_their_kind_modules():
    assert (
        import_problems(SRC, VENDOR_IMPORTS, LIBRARY_IMPORTS, PENDING, DYNAMIC_IMPORT_OK, TODAY)
        == []
    )


def test_every_table_factory_is_a_core_module():
    outside = [m for m in factory_modules() if m.split(".")[0] != PKG]
    assert outside == [], "a kind's factory must live in hadavin_sdk, never in a vendor package"


def test_a_neutral_kind_has_no_vendor_only_path():
    """neutral is hand-set; at least keep it off kinds whose module is a plain vendor SDK without an
    endpoint to point elsewhere (the S3 anchor is neutral only through `endpoint_url`)."""
    from hadavin_sdk.backends.table import S3ObjectLockSettings

    assert "endpoint_url" in S3ObjectLockSettings.model_fields
    for cap, kinds in TABLE.items():
        for kind, entry in kinds.items():
            if entry.neutral and entry.factory.split(":")[0] in set().union(
                *VENDOR_IMPORTS.values()
            ):
                assert (cap, kind) == ("anchor", "s3_object_lock"), (cap, kind)


def test_every_vendor_module_is_a_kind():
    assert vendor_module_problems(SRC, VENDOR_IMPORTS, factory_modules(), VENDOR_HELPERS) == []


def test_botocore_shares_the_boto3_set():
    assert VENDOR_IMPORTS["botocore"] is VENDOR_IMPORTS["boto3"]


def _plant(tmp_path: Path, rel: str, text: str) -> Path:
    path = tmp_path / PKG / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return tmp_path


def _imports(root: Path, pending=None, today: date = date(2026, 11, 1)) -> list[str]:
    return import_problems(
        root, VENDOR_IMPORTS, LIBRARY_IMPORTS, pending or {}, DYNAMIC_IMPORT_OK, today
    )


def test_plant_vendor_sdk_in_core_module_is_caught(tmp_path):
    root = _plant(tmp_path, "runtime/x.py", "import boto3\n")
    assert _imports(root) == [
        f"{PKG}.runtime.x: imports boto3 (vendor SDK) outside its allowed modules"
    ]


def test_plant_lazy_vendor_import_is_caught(tmp_path):
    root = _plant(tmp_path, "runtime/x.py", "def f():\n    from azure.identity import X\n")
    assert len(_imports(root)) == 1


def test_plant_unknown_third_party_is_caught(tmp_path):
    root = _plant(tmp_path, "runtime/x.py", "import requests\n")
    assert "requests (unknown)" in _imports(root)[0]


def test_plant_library_outside_its_layer_is_caught(tmp_path):
    root = _plant(tmp_path, "runtime/x.py", "import psycopg\n")
    assert "psycopg (library)" in _imports(root)[0]


def test_plant_relative_import_is_caught(tmp_path):
    root = _plant(tmp_path, "runtime/x.py", "from . import y\n")
    assert "relative import" in _imports(root)[0]


def test_plant_aliased_dynamic_import_is_caught(tmp_path):
    root = _plant(
        tmp_path, "runtime/x.py", "from importlib import import_module as im\nim('boto3')\n"
    )
    assert any("imports importlib" in p for p in _imports(root))


def test_plant_dynamic_import_is_caught(tmp_path):
    root = _plant(tmp_path, "runtime/x.py", "import importlib\nimportlib.import_module('boto3')\n")
    problems = _imports(root)
    assert any("dynamic import" in p for p in problems)
    assert any("imports boto3" in p for p in problems)  # the constant is also checked as an import


def test_plant_dunder_import_is_caught(tmp_path):
    root = _plant(tmp_path, "runtime/x.py", "__import__(name)\n")
    assert any("dynamic import" in p for p in _imports(root))


def test_an_allowed_vendor_module_and_dynamic_hook_pass(tmp_path):
    _plant(tmp_path, "llm/bedrock.py", "import boto3\nfrom botocore.config import Config\n")
    root = _plant(tmp_path, "actions/executor.py", "import importlib\nimportlib.import_module(x)\n")
    assert _imports(root) == []


def test_plant_stale_pending_entry_is_caught(tmp_path):
    root = _plant(tmp_path, "runtime/x.py", "import json\n")
    entry = Pending("r", "P0", date(2026, 10, 31), date(2026, 11, 30))
    problems = _imports(root, {("boto3", f"{PKG}.runtime.x"): entry})
    assert problems == [f"PENDING ('boto3', '{PKG}.runtime.x') is fixed: delete the entry"]


def test_plant_overdue_pending_entry_is_caught(tmp_path):
    root = _plant(tmp_path, "runtime/x.py", "import boto3\n")
    entry = Pending("r", "P0", date(2026, 10, 1), date(2026, 10, 15))
    problems = _imports(root, {("boto3", f"{PKG}.runtime.x"): entry})
    assert len(problems) == 1 and "overdue" in problems[0]


def test_a_live_pending_entry_allows_its_import(tmp_path):
    root = _plant(tmp_path, "runtime/x.py", "import boto3\n")
    entry = Pending("r", "P0", date(2026, 10, 31), date(2026, 11, 30))
    assert _imports(root, {("boto3", f"{PKG}.runtime.x"): entry}) == []


def test_plant_vendor_module_that_is_not_a_kind_is_caught(tmp_path):
    root = _plant(tmp_path, "llm/bedrock.py", "import boto3\n")
    problems = vendor_module_problems(root, VENDOR_IMPORTS, set(), VENDOR_HELPERS)
    assert any("neither a TABLE kind nor a VENDOR_HELPER" in p for p in problems)


def test_plant_stale_vendor_helper_is_caught(tmp_path):
    problems = vendor_module_problems(tmp_path, VENDOR_IMPORTS, set(), {f"{PKG}.runtime.x"})
    assert problems == [f"VENDOR_HELPERS {PKG}.runtime.x is not a vendor module: delete the entry"]


# ---------------------------------------------------------------------------------------------- rule b

NULL_KINDS = {("signer", "none"), ("anchor", "none")}  # never count as a prod kind


@dataclass(frozen=True)
class ExceptionEntry:
    status: str  # "accepted" (a reasoned permanent exception) or "pending" (a scheduled fix)
    reason: str
    trigger: str  # what ends it, or the fix ref
    decided: date
    review_by: date


EXCEPTIONS: dict[str, ExceptionEntry] = {
    "store": ExceptionEntry(
        "accepted",
        "PostgreSQL: open source, on every cloud and on-prem; the Store Protocol is the seam",
        "a client who refuses Postgres (SQLite kind)",
        date(2026, 10, 31),
        date(2027, 4, 30),
    ),
    "audit": ExceptionEntry(
        "accepted",
        "chain is our own code on the store; the signer and anchor are the pluggable parts",
        "none",
        date(2026, 10, 31),
        date(2027, 4, 30),
    ),
    "channel": ExceptionEntry(
        "accepted",
        "Slack is the only interactive approval kind in the pilot (owner, design v5 11.6)",
        "first client without Slack (Teams or email-link kind, Phase 2)",
        date(2026, 10, 31),
        date(2027, 1, 31),
    ),
}


def coverage_problems(
    table, dev_only, not_prod, null_kinds, exceptions: dict[str, ExceptionEntry], today: date
) -> list[str]:
    out = []
    for cap, kinds in table.items():
        prod = {k: e for k, e in kinds.items() if (cap, k) not in dev_only | not_prod | null_kinds}
        ok = any(e.neutral for e in prod.values()) and len(prod) >= 2
        if not ok and cap not in exceptions:
            out.append(
                f"{cap}: needs a neutral prod kind and >= 2 prod kinds, or an EXCEPTIONS entry"
            )
        if ok and cap in exceptions:
            out.append(f"{cap}: passes now, delete its EXCEPTIONS entry")
    for name, ex in exceptions.items():
        if name not in table:
            out.append(f"{name}: exception names no capability: delete the entry")
        if not ex.reason or not ex.trigger:
            out.append(f"{name}: exception needs a reason and a trigger")
        if ex.review_by < today:
            out.append(f"{name}: exception overdue (review_by {ex.review_by})")
    return out


def test_every_capability_has_a_neutral_prod_kind_and_two_prod_kinds():
    assert coverage_problems(TABLE, DEV_ONLY, NOT_PROD, NULL_KINDS, EXCEPTIONS, TODAY) == []


def test_the_anchor_is_a_capability_with_a_prod_kind_besides_s3():
    assert {k for k in TABLE["anchor"] if k != "none"} >= {"s3_object_lock", "azure_immutable_blob"}


@dataclass(frozen=True)
class _E:
    neutral: bool = False


def _cov(table, exceptions=None, dev_only=frozenset(), today=date(2026, 11, 1)) -> list[str]:
    return coverage_problems(table, dev_only, NOT_PROD, NULL_KINDS, exceptions or {}, today)


def test_plant_one_vendor_kind_without_an_entry_is_caught():
    assert len(_cov({"x": {"aws": _E()}})) == 1


def test_plant_only_neutral_kind_being_dev_only_is_caught():
    table = {"x": {"mem": _E(True), "aws": _E(), "gcp": _E()}}
    assert len(_cov(table, dev_only=frozenset({("x", "mem")}))) == 1


def test_plant_a_capability_counting_only_none_is_caught():
    table = {"signer": {"none": _E(True), "aws": _E()}}
    assert len(_cov(table)) == 1


def test_plant_two_vendor_kinds_with_no_neutral_one_is_caught():
    assert len(_cov({"x": {"aws": _E(), "gcp": _E()}})) == 1


def test_two_kinds_with_one_neutral_pass():
    assert _cov({"x": {"vault": _E(True), "aws": _E()}}) == []


def test_plant_stale_exception_is_caught():
    ex = {"x": ExceptionEntry("pending", "r", "t", date(2026, 10, 1), date(2026, 12, 1))}
    assert _cov({"x": {"vault": _E(True), "aws": _E()}}, ex) == [
        "x: passes now, delete its EXCEPTIONS entry"
    ]


def test_plant_overdue_exception_is_caught():
    ex = {"x": ExceptionEntry("accepted", "r", "t", date(2026, 10, 1), date(2026, 10, 15))}
    problems = _cov({"x": {"aws": _E()}}, ex)
    assert len(problems) == 1 and "overdue" in problems[0]


def test_plant_exception_for_a_missing_capability_is_caught():
    ex = {"gone": ExceptionEntry("accepted", "r", "t", date(2026, 10, 1), date(2027, 1, 1))}
    assert len(_cov({}, ex)) == 1


def test_plant_exception_without_a_reason_is_caught():
    ex = {"x": ExceptionEntry("accepted", "", "t", date(2026, 10, 1), date(2027, 1, 1))}
    assert any("needs a reason" in p for p in _cov({"x": {"aws": _E()}}, ex))


# ---------------------------------------------------------------------------------------------- rule c

VENDOR_MODULES = {
    # the vendor SDK modules (rule a's sets), plus vendor modules built on the standard library only
    *set().union(*VENDOR_IMPORTS.values()),
    f"{PKG}.llm.gemini",
    f"{PKG}.llm.anthropic",
    f"{PKG}.approvals.slack",
    f"{PKG}.approvals.slack_channel",
    f"{PKG}.guard.redact",  # detects vendor secrets by design
}
# (module, literal) -> why this literal may stay in an otherwise neutral module. Stale entries fail.
LITERAL_OK: dict[tuple[str, str], str] = {
    (
        f"{PKG}.approvals.gate",
        "aws",
    ): "G4 command shape: one of many programs (tests/test_g4_parity.py)",
    (f"{PKG}.approvals.gate", "s3"): "G4 read-only shape: `aws s3 ls` (tests/test_g4_parity.py)",
    (f"{PKG}.config", "slack"): "the retired slice 1 config key, refused with its new place",
    (
        f"{PKG}.llm.openai_compat",
        r"^(?:gpt-[\w.-]+|o\d[\w.-]*|chatgpt-[\w.-]+)$",
    ): "the OpenAI protocol's own moving aliases; this kind exists to speak that protocol",
}
_TABLE_MODULE = f"{PKG}.backends.table"
_TABLE_VENDOR_NAME = re.compile(
    r"^_?(aws|bedrock|anthropic|gemini|s3|slack|gcp|azure|vertex)", re.IGNORECASE
)
PATTERNS = {
    "bare vendor name": r"^(slack|teams|aws|azure|gcp|github|gitlab|bedrock|anthropic|vertex|gemini"
    r"|openai|kms|s3|foundry)(:|$)",
    "vendor header": r"x-(slack|amz|goog|ms)-",
    "ARN": r"\barn:aws[a-z-]*:",
    "AWS region": r"\b(us|eu|ap|sa|ca|me|af|il|mx|cn)(-gov|-iso[a-z]*)?-"
    r"(north|south|east|west|central|northeast|northwest|southeast|southwest)-\d\b",
    "GCP region": r"\b(us|europe|asia|australia|northamerica|southamerica|me|africa)-[a-z]+\d\b",
    "Azure region": r"\b(eastus|westus|southcentralus|northcentralus|westcentralus|westeurope"
    r"|northeurope|centralindia|southindia|southeastasia|eastasia|uksouth|ukwest|japaneast|japanwest"
    r"|australiaeast|canadacentral|canadaeast|brazilsouth|germanywestcentral|swedencentral"
    r"|koreacentral|francecentral|uaenorth|norwayeast|switzerlandnorth|southafricanorth)\d?\b",
    "model id": r"\b(claude|gpt-|gemini-|llama|mistral|qwen|deepseek|anthropic\.|us\.anthropic\."
    r"|amazon\.(nova|titan)|cohere\.|meta\.)|\bo[134](-mini|-pro)?\b",
    "account id": r"\b\d{12}\b",
    "host": r"(amazonaws\.com(\.cn)?|aws\.amazon\.com|azure\.com|(azure|windows)\.net|googleapis\.com"
    r"|cloud\.google\.com|slack\.com|github\.com|anthropic\.com|openai\.com)\b",
}
_SQL_LITERAL = re.compile(
    r"'(slack|teams|github|gitlab|aws|azure|gcp|bedrock|anthropic|kms|s3)'", re.IGNORECASE
)


def _docstrings(tree: ast.AST) -> set[int]:
    ids = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
            first = n.body[0] if n.body else None
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
                ids.add(id(first.value))
    return ids


def _skipped_table_nodes(tree: ast.Module) -> set[int]:
    """In backends.table: vendor-named settings classes and helpers, and the TABLE itself, name vendors."""
    skipped: set[int] = set()
    for top in tree.body:
        named = isinstance(top, ast.ClassDef | ast.FunctionDef) and _TABLE_VENDOR_NAME.match(
            top.name
        )
        table = isinstance(top, ast.AnnAssign | ast.Assign) and "TABLE" in ast.unparse(top)[:12]
        if named or table:
            skipped |= {id(n) for n in ast.walk(top)}
    return skipped


def literal_problems(
    src: Path, vendor_modules: set[str], literal_ok: dict[tuple[str, str], str]
) -> list[str]:
    out: list[str] = []
    used: set[tuple[str, str]] = set()
    for path in sorted(src.rglob("*.py")):
        mod = module_name(src, path)
        if mod in vendor_modules:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        skip = _docstrings(tree) | (_skipped_table_nodes(tree) if mod == _TABLE_MODULE else set())
        for n in ast.walk(tree):
            if not (isinstance(n, ast.Constant) and isinstance(n.value, str)) or id(n) in skip:
                continue
            for label, pattern in PATTERNS.items():
                if re.search(pattern, n.value, re.IGNORECASE):
                    if (mod, n.value) in literal_ok:
                        used.add((mod, n.value))
                    else:
                        out.append(f"{mod}:{n.lineno}: {label} in {n.value[:50]!r}")
    out += [
        f"LITERAL_OK {k[0]} {k[1][:30]!r} is gone: delete the entry"
        for k in literal_ok
        if k not in used
    ]
    return out


def sql_problems(folder: Path) -> list[str]:
    out = []
    for path in sorted(folder.glob("*.sql")):
        text = re.sub(r"/\*.*?\*/", "", path.read_text(encoding="utf-8"), flags=re.DOTALL)
        text = re.sub(r"--[^\n]*", "", text)
        for m in _SQL_LITERAL.finditer(text):
            out.append(f"{path.name}: vendor literal {m.group(0)}")
        for label, pattern in PATTERNS.items():
            if label != "bare vendor name" and re.search(pattern, text, re.IGNORECASE):
                out.append(f"{path.name}: {label}")
    return out


def test_core_logic_names_no_vendor():
    assert literal_problems(SRC, VENDOR_MODULES, LITERAL_OK) == []


def test_migrations_name_no_vendor():
    folder = SRC / PKG / "store" / "migrations"
    assert list(folder.glob("*.sql")), "no migrations found: the scan would check nothing"
    assert sql_problems(folder) == []


def test_every_named_vendor_module_exists():
    missing = [
        m for m in VENDOR_MODULES if not (SRC / Path(*m.split(".")).with_suffix(".py")).is_file()
    ]
    assert missing == []


def _lit(tmp_path: Path, rel: str, text: str, ok=None) -> list[str]:
    root = _plant(tmp_path, rel, text)
    return literal_problems(root, VENDOR_MODULES, ok or {})


def test_plant_region_constant_is_caught(tmp_path):
    assert "AWS region" in _lit(tmp_path, "runtime/x.py", "R = 'us-east-1'\n")[0]


def test_plant_arn_is_caught(tmp_path):
    assert "ARN" in _lit(tmp_path, "runtime/x.py", "A = 'arn:aws:s3:::b'\n")[0]


def test_plant_slack_id_fstring_is_caught(tmp_path):
    assert (
        "bare vendor name"
        in _lit(tmp_path, "approvals/x.py", "def f(x):\n    return f'slack:{x}'\n")[0]
    )


def test_plant_amz_header_is_caught(tmp_path):
    assert "vendor header" in _lit(tmp_path, "runtime/x.py", "H = 'x-amz-date'\n")[0]


def test_plant_model_id_host_and_account_are_caught(tmp_path):
    text = (
        "M = 'claude-sonnet-4'\nH = 'https://x.googleapis.com'\nN = '123456789012'\nG = 'eastus2'\n"
    )
    assert len(_lit(tmp_path, "runtime/x.py", text)) == 4


def test_a_docstring_and_a_vendor_module_are_not_flagged(tmp_path):
    _plant(tmp_path, "llm/gemini.py", "H = 'x-goog-api-key'\n")
    assert _lit(tmp_path, "runtime/x.py", '"""Talks to slack.com."""\nX = 1\n') == []


def test_plant_stale_literal_allowance_is_caught(tmp_path):
    problems = _lit(tmp_path, "runtime/x.py", "X = 1\n", {(f"{PKG}.runtime.x", "aws"): "why"})
    assert len(problems) == 1 and "is gone" in problems[0]


def test_a_listed_literal_is_allowed(tmp_path):
    assert _lit(tmp_path, "runtime/x.py", "X = 'aws'\n", {(f"{PKG}.runtime.x", "aws"): "why"}) == []


def test_plant_sql_check_with_a_vendor_literal_is_caught(tmp_path):
    (tmp_path / "0009.sql").write_text(
        "ALTER TABLE t ADD CHECK (lower(channel) IN ('slack', 'csv'));\n", encoding="utf-8"
    )
    assert sql_problems(tmp_path) == ["0009.sql: vendor literal 'slack'"]


def test_a_vendor_name_in_a_sql_comment_is_not_flagged(tmp_path):
    (tmp_path / "0009.sql").write_text(
        "-- 'slack' is one channel\n/* 'aws' */\nSELECT 1;\n", encoding="utf-8"
    )
    assert sql_problems(tmp_path) == []


# ------------------------------------------------------------------- the test environment and anchors


def test_the_test_environment_holds_no_cloud_credential_variables():
    import os

    from tests.conftest import _ISOLATED, _ISOLATED_PREFIXES

    assert {"AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_PROFILE"} <= set(_ISOLATED)
    assert {"AWS_ENDPOINT_URL", "AZURE_", "GOOGLE_APPLICATION_CREDENTIALS"} <= set(
        _ISOLATED_PREFIXES
    )
    leaked = [n for n in os.environ if n in _ISOLATED or n.startswith(_ISOLATED_PREFIXES)]
    assert leaked == []
