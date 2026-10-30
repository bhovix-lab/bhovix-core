"""Slice 2 P3b: cloud-neutral audit (lock-in audit 2026-10-31 items 2-4). The anchor is its own table kind
(S3 incl. MinIO via `endpoint_url`, Azure immutable Blob, GCS retention lock); signers `vault_transit`,
`azure_key_vault_key`, `gcp_kms`; `ed25519_local` in prod only with its key from a secrets kind beside a WORM
anchor; vendor SDKs only in their kind modules (signer_aws, store/auth_aws)."""

import ast
import json
import sys
from pathlib import Path

import pytest
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hadavin_sdk import cli
from hadavin_sdk.actions.secrets import FakeSecretProvider
from hadavin_sdk.audit import anchor_azure, anchor_gcs, chain, signer_azure
from hadavin_sdk.audit.anchor_azure import AzureBlobAnchor
from hadavin_sdk.audit.anchor_gcs import GcsAnchor
from hadavin_sdk.audit.signer import LocalSigner
from hadavin_sdk.audit.signer_azure import AzureKeyVaultSigner
from hadavin_sdk.audit.signer_gcp import GcpKmsSigner
from hadavin_sdk.audit.signer_vault import VaultTransitSigner
from hadavin_sdk.backends import make
from hadavin_sdk.backends.table import (
    AzureImmutableBlobSettings,
    AzureKeyVaultKeySettings,
    ChainSettings,
    Ed25519LocalSettings,
    GcpKmsSettings,
    GcsRetentionLockSettings,
    KindSettings,
    VaultTransitSettings,
)
from hadavin_sdk.config import load_config
from hadavin_sdk.errors import ConfigError
from hadavin_sdk.models import AuditEvent
from hadavin_sdk.store import postgres
from tests.conftest import make_cfg
from tests.contracts.http_fake import azure_container, azure_key_clients, gcp_kms_client, gcs_bucket
from tests.contracts.kinds.audit_neutral import AZURE_KEY, GCP_KEY, transit_key
from tests.contracts.kinds.secrets_neutral import vault_target

SRC = Path(__file__).resolve().parents[1] / "src" / "hadavin_sdk"


def _event(i):
    return AuditEvent(run_id="run-1", domain="d", operation=f"o{i}", principal="p", source="s")


def _chain(signer, anchor, rows=3):
    log = chain.ChainAudit(chain._Db.memory(), signer, anchor, checkpoint_every=2)
    for i in range(rows):
        log.write_intent(_event(i))
    log.checkpoint()
    return log


# --- every neutral signer x anchor pair signs, anchors and verifies -------------------------------------


@pytest.mark.parametrize("which", ["vault_transit", "azure_key_vault_key", "gcp_kms"])
@pytest.mark.parametrize("where", ["azure_immutable_blob", "gcs_retention_lock"])
def test_a_chain_signed_and_anchored_on_any_cloud_verifies_and_shows_a_rewrite(which, where):
    if which == "vault_transit":
        client, name = transit_key()
        signer = VaultTransitSigner(client, "transit", name, 1)
    elif which == "azure_key_vault_key":
        signer = AzureKeyVaultSigner(AZURE_KEY, *azure_key_clients(AZURE_KEY))
    else:
        signer = GcpKmsSigner(GCP_KEY, gcp_kms_client(GCP_KEY))
    anchor = (
        AzureBlobAnchor(azure_container("anchors"))
        if where == "azure_immutable_blob"
        else GcsAnchor(gcs_bucket("contract-anchors"))
    )
    log = _chain(signer, anchor)
    v = log.verify()
    assert v.ok and v.signed_through == 3, v.problems
    assert set(anchor.all()) == {2, 3}
    db = log._db.conn
    for (name,) in db.execute("SELECT name FROM sqlite_master WHERE type = 'trigger'").fetchall():
        db.execute(f"DROP TRIGGER {name}")
    db.execute("DELETE FROM audit_checkpoints WHERE seq = 3")
    db.execute("DELETE FROM audit_entries WHERE seq = 3")
    assert "anchor 3 has no checkpoint here: the database lost history" in log.verify().problems


def test_a_changed_event_id_column_is_found():
    log = _chain(LocalSigner(Ed25519PrivateKey.generate()), None, rows=2)
    db = log._db.conn
    db.execute("DROP TRIGGER audit_entries_no_update")
    db.execute("UPDATE audit_entries SET event_id = 'evt-other' WHERE seq = 1")
    assert "row 1 event id column does not match its body" in log.verify().problems


# --- factories through the table ------------------------------------------------------------------------


def test_vault_transit_builds_from_settings_and_pins_the_key_version(monkeypatch):
    """Through the table, on the CI Vault dev server or the local fake: a token sign-in, one key version."""
    address, token = vault_target()
    monkeypatch.setenv("VAULT_TOKEN", token)
    _, name = transit_key()
    settings = VaultTransitSettings(
        kind="vault_transit", address=address, key_name=name, key_version=1
    )
    signer = make("signer", settings)
    assert signer.key_id == f"vault-transit:transit/{name}:v1"
    with pytest.raises(ConfigError):
        make(
            "signer", settings.model_copy(update={"key_version": 2})
        )  # a version that is not there
    for bad in ({"key_name": "../x"}, {"transit_mount": "a/../b"}):
        with pytest.raises(ValueError):
            VaultTransitSettings(
                **{"kind": "vault_transit", "address": address, "key_name": "k", "key_version": 1}
                | bad
            )


def test_azure_signer_needs_a_pinned_version_and_an_ec_p256_key(monkeypatch):
    good, wrong_curve = azure_key_clients(AZURE_KEY), azure_key_clients(AZURE_KEY, curve="P-384")
    pick = {"clients": good}  # built before patching: the patch replaces the SDK's KeyClient itself
    monkeypatch.setattr(signer_azure, "CryptographyClient", lambda key_id, cred: pick["clients"][0])
    monkeypatch.setattr(signer_azure.azure_keys, "KeyClient", lambda url, cred: pick["clients"][1])
    signer = make("signer", AzureKeyVaultKeySettings(kind="azure_key_vault_key", key_id=AZURE_KEY))
    assert signer.alg == "ecdsa-p256"
    with pytest.raises(ValueError):  # no version: a rotation would orphan old checkpoints
        AzureKeyVaultKeySettings(
            kind="azure_key_vault_key", key_id="https://kv.vault.azure.net/keys/audit"
        )
    pick["clients"] = wrong_curve
    with pytest.raises(ConfigError, match="not an EC P-256 key"):
        make("signer", AzureKeyVaultKeySettings(kind="azure_key_vault_key", key_id=AZURE_KEY))


def test_gcp_kms_refuses_a_non_ed25519_key_and_missing_adc(monkeypatch):
    from google.cloud import kms

    client = gcp_kms_client(GCP_KEY, algorithm="EC_SIGN_P256_SHA256")
    with pytest.raises(ConfigError, match="not an EC_SIGN_ED25519 key"):
        GcpKmsSigner(GCP_KEY, client).public_key()
    from google.auth.exceptions import DefaultCredentialsError

    def no_adc(*a, **k):
        raise DefaultCredentialsError("none")

    monkeypatch.setattr(kms, "KeyManagementServiceClient", no_adc)
    with pytest.raises(ConfigError, match="no Application Default Credentials"):
        make("signer", GcpKmsSettings(kind="gcp_kms", key_version=GCP_KEY))


def test_azure_anchor_needs_version_level_immutability(monkeypatch):
    settings = AzureImmutableBlobSettings(
        kind="azure_immutable_blob",
        account_url="https://contract.blob.core.windows.net",
        container="anchors",
    )
    puts = []
    monkeypatch.setattr(
        anchor_azure, "ContainerClient", lambda *a, **k: azure_container("anchors", puts=puts)
    )
    anchor = make("anchor", settings)
    anchor.put(1, "a" * 64, "b" * 128)
    assert puts[0]["x-ms-immutability-policy-mode"].lower() == "unlocked"  # GOVERNANCE
    assert "x-ms-immutability-policy-until-date" in puts[0]
    monkeypatch.setattr(
        anchor_azure, "ContainerClient", lambda *a, **k: azure_container("anchors", immutable=False)
    )
    with pytest.raises(ConfigError, match="version-level immutability"):
        make("anchor", settings)


@pytest.mark.parametrize(
    "retention_s,locked,mode,error",
    [
        (86400, False, "GOVERNANCE", None),
        (None, False, "GOVERNANCE", "retention policy of at least 1 day"),
        (3600, False, "GOVERNANCE", "retention policy of at least 1 day"),
        (86400, False, "COMPLIANCE", "needs a locked retention policy"),
        (86400, True, "COMPLIANCE", None),
    ],
)
def test_gcs_anchor_checks_the_bucket_retention_policy(
    monkeypatch, retention_s, locked, mode, error
):
    bucket = gcs_bucket("contract-anchors", retention_s=retention_s, locked=locked)

    class Client:
        def bucket(self, name):
            return bucket

    monkeypatch.setattr(anchor_gcs.storage, "Client", Client)
    settings = GcsRetentionLockSettings(
        kind="gcs_retention_lock", bucket="contract-anchors", mode=mode
    )
    if error:
        with pytest.raises(ConfigError, match=error):
            make("anchor", settings)
    else:
        assert isinstance(make("anchor", settings), GcsAnchor)


def test_the_anchor_reaches_the_chain_through_deps_only():
    """No anchor module is imported by the chain: the anchor is chosen in config like any kind."""
    tree = ast.parse((SRC / "audit" / "chain.py").read_text(encoding="utf-8"))
    names = [n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module]
    names += [a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names]
    assert not [n for n in names if "anchor" in n]
    store = make("store", KindSettings(kind="memory"))
    sentinel = object()
    signer = LocalSigner(Ed25519PrivateKey.generate())
    log = make("audit", ChainSettings(kind="chain"), store=store, signer=signer, anchor=sentinel)
    assert log.anchor is sentinel


# --- ed25519_local: the key from a secrets kind --------------------------------------------------------


def test_ed25519_local_loads_its_key_from_a_secret_and_never_echoes_it():
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    settings = Ed25519LocalSettings(kind="ed25519_local", private_key_secret_name="audit-key")  # noqa: S106
    signer = make("signer", settings, FakeSecretProvider({"audit-key": pem}))
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    assert signer.public_key() == raw
    junk = "not" + "-a-pem-value"
    with pytest.raises(ConfigError) as caught:
        make("signer", settings, FakeSecretProvider({"audit-key": junk}))
    assert junk not in str(caught.value) and "secret 'audit-key'" in str(caught.value)


def _prod_config(tmp_path, backends):
    cfg_dir = make_cfg(tmp_path)
    path = cfg_dir / "config.yaml"
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    raw["environment"] = "prod"
    raw["backends"].update(backends)
    path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    return cfg_dir


def test_prod_refuses_no_signer_and_no_anchor_at_config_load(tmp_path):
    with pytest.raises(ConfigError) as caught:
        load_config(_prod_config(tmp_path, {"audit": {"kind": "chain"}}))
    assert "signer: none" in str(caught.value) and "anchor: none" in str(caught.value)


# --- store: RDS IAM in its own helper; callers pass the helper ---------------------------------------------


def test_rds_iam_signs_in_through_store_auth_aws(monkeypatch):
    import boto3

    calls = []

    class Rds:
        def generate_db_auth_token(self, **kw):
            calls.append(kw)
            return "token" + "-from-iam"

    monkeypatch.setattr(boto3, "client", lambda service, **kw: calls.append((service, kw)) or Rds())
    assert postgres.password_source(False, None) is None
    password = postgres.password_source(True, "region-x")
    assert password("db.example", 5432, "rt") == "token-from-iam"
    assert calls == [
        ("rds", {"region_name": "region-x"}),
        {"DBHostname": "db.example", "Port": 5432, "DBUsername": "rt"},
    ]


def test_rds_iam_without_the_aws_extra_names_the_pip_install(monkeypatch):
    import hadavin_sdk.store

    # Forget the helper everywhere it is cached (a from-import reads the package attribute first).
    monkeypatch.delitem(sys.modules, "hadavin_sdk.store.auth_aws", raising=False)
    monkeypatch.delattr(hadavin_sdk.store, "auth_aws", raising=False)
    monkeypatch.setitem(sys.modules, "boto3", None)
    with pytest.raises(ConfigError, match=r"pip install hadavin-sdk\[aws\]"):
        postgres.password_source(True, "region-x")


def test_migrate_and_its_cli_pass_the_iam_helper_to_connect(tmp_path, monkeypatch, capsys):
    from hadavin_sdk.store import migrate as migrate_mod

    seen = {}

    class Stop(Exception):
        pass

    def connect(dsn, *, password=None):
        seen["password"] = password
        raise Stop

    monkeypatch.setattr(migrate_mod, "connect", connect)
    helper = lambda h, p, u: "t"
    with pytest.raises(Stop):
        migrate_mod.migrate("postgresql://unused", password=helper)
    assert seen["password"] is helper
    calls = {}
    monkeypatch.setattr(
        postgres,
        "password_source",
        lambda iam, region: calls.update(iam=iam, region=region) or helper,
    )
    monkeypatch.setattr(migrate_mod, "migrate", lambda dsn, **kw: calls.update(kw) or [])
    cfg_dir = make_cfg(tmp_path)
    path = cfg_dir / "config.yaml"
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    raw["backends"]["store"] = {
        "kind": "postgres",
        "dsn_secret_name": "pg-dsn",
        "iam_auth": True,
        "region": "region-x",
    }
    path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    monkeypatch.setenv("HADAVIN_CONFIG_DIR", str(cfg_dir))
    monkeypatch.setenv("HADAVIN_MIGRATE_DSN", "postgresql://" + "migrator@db/core")
    assert cli.main(["--config", str(cfg_dir), "migrate"]) == 0
    assert calls == {"iam": True, "region": "region-x", "runtime_role": None, "password": helper}


# --- vendor SDKs only in their kind modules (audit §3a, for the modules this PR touched) ------------------

VENDORS = {"boto3", "botocore", "azure", "google"}
OWN_MODULES = [
    "audit/signer.py",
    "audit/chain.py",
    "audit/anchors.py",
    "store/postgres.py",
    "store/migrate.py",
]


@pytest.mark.parametrize("module", OWN_MODULES)
def test_neutral_modules_import_no_cloud_sdk_even_lazily(module):
    tree = ast.parse((SRC / module).read_text(encoding="utf-8"))
    names = [a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names]
    names += [
        n.module
        for n in ast.walk(tree)
        if isinstance(n, ast.ImportFrom) and n.module and not n.level
    ]
    assert not [n for n in names if n.split(".")[0] in VENDORS], module


def test_every_anchor_body_is_the_same_json_shape():
    from hadavin_sdk.audit import anchors

    assert json.loads(anchors.body(7, "h", "s")) == {"seq": 7, "hash": "h", "signature": "s"}
    assert anchors.key(7) == "anchors/000000000007.json"
