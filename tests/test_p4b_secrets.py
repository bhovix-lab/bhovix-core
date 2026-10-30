"""Slice 2 P4b: cloud-neutral secrets (`vault`, `azure_key_vault`, `gcp_secret_manager`, `mounted_file`) and the
install-hint guard for every extra. The shared Secrets suite runs on each kind in tests/contracts; these are the
kind-specific checks."""

import os
import ssl
import sys
from pathlib import Path

import pytest

from hadavin_sdk.actions.secrets_file import MountedFileProvider
from hadavin_sdk.actions.secrets_vault import VaultError, VaultProvider
from hadavin_sdk.backends import make
from hadavin_sdk.backends.table import (
    AwsSecretsManagerSettings,
    AzureKeyVaultSettings,
    GcpSecretManagerSettings,
    MountedFileSettings,
    VaultSettings,
)
from hadavin_sdk.errors import ConfigError
from tests.contracts.aws_stub import REGION
from tests.contracts.kinds.secrets_neutral import PROJECT, VAULT_URL, write_secret_file
from tests.contracts.vault_fake import ROOT, fake_vault
from tests.test_repo_rules import SECRET_HOLDERS

VALUE = "p4b" + "-value"  # built from parts
POSIX = os.name != "nt"


@pytest.fixture
def vault():
    v = fake_vault()
    v.kv["secret/app/db"] = {"value": VALUE, "other": "x"}
    return v


def _settings(vault, **kw):
    return VaultSettings(kind="vault", address=vault.address, path_prefix="app/", **kw)


# --- vault -------------------------------------------------------------------------------------------


def test_vault_token_auth_reads_kv_v2_with_the_token_from_the_environment(vault, monkeypatch):
    monkeypatch.setenv("VAULT_TOKEN", ROOT)
    provider = make("secrets", _settings(vault, namespace="team-a"))
    assert provider.get("db") == VALUE
    assert vault.seen_namespaces[-1] == "team-a"
    with pytest.raises(ConfigError, match="not found in Vault"):
        provider.get("missing")
    monkeypatch.delenv("VAULT_TOKEN")
    with pytest.raises(ConfigError, match="VAULT_TOKEN is not set"):
        make("secrets", _settings(vault)).get("db")


def test_vault_approle_signs_in_and_signs_in_again_after_a_403(vault, monkeypatch):
    vault.approle["role-1"] = "sid" + "-1"
    monkeypatch.setenv("VAULT_SECRET_ID", "sid-1")
    provider = make("secrets", _settings(vault, auth="approle", role_id="role-1", ttl_s=0))
    assert provider.get("db") == VALUE
    vault.tokens.discard(provider._token)  # the token expires
    assert provider.get("db") == VALUE  # one re-login, then the read
    monkeypatch.setenv("VAULT_SECRET_ID", "wrong")
    vault.tokens.discard(provider._token)
    with pytest.raises(ConfigError, match="approle sign-in refused"):
        provider.get("db")


def test_vault_kubernetes_signs_in_with_the_service_account_token(vault, tmp_path):
    jwt = tmp_path / "token"
    jwt.write_text("header.payload.sig\n", encoding="utf-8")
    vault.k8s["hadavin"] = "header.payload.sig"
    provider = make("secrets", _settings(vault, auth="kubernetes", role="hadavin", jwt_path=jwt))
    assert provider.get("db") == VALUE


def test_vault_refuses_odd_names_missing_fields_and_reports_status_only(vault):
    provider = VaultProvider(vault.address, lambda p: ROOT, path_prefix="app/", field="nope")
    for bad in ("../db", "a/b", "..", ""):
        with pytest.raises(ConfigError):
            provider.get(bad)
    with pytest.raises(ConfigError, match="no field 'nope'"):
        provider.get("db")
    denied = VaultProvider(vault.address, lambda p: "not-a-token", renewable=False)
    with pytest.raises(VaultError, match="answered 403$"):
        denied.get("db")


def test_vault_never_follows_a_redirect_with_the_token(vault, monkeypatch):
    """A standby node's 307 would carry X-Vault-Token to another address: it is an error, not followed."""
    monkeypatch.setenv(
        "HTTP_PROXY", "http://127.0.0.1:9"
    )  # a loopback Vault is never reached via a proxy
    provider = VaultProvider(vault.address, lambda p: ROOT, path_prefix="app/")
    reads = vault.reads
    with pytest.raises(VaultError, match="answered 307$"):
        provider.get("moved")
    assert vault.reads == reads  # the redirect target (a real secret) was never read
    assert provider.get("db") == VALUE  # and the proxy variable was ignored


def test_vault_odd_response_shapes_are_errors_never_coerced(vault):
    vault.kv["secret/app/nullv"] = {"value": None}
    vault.kv["secret/app/listy"] = ["value"]
    vault.kv["secret/app/num"] = {"value": 7}
    provider = VaultProvider(vault.address, lambda p: ROOT, path_prefix="app/", ttl_s=0)
    with pytest.raises(VaultError, match="not JSON"):
        provider.get("html")
    with pytest.raises(VaultError, match="unexpected JSON shape"):
        provider.get("listy")
    for name in ("nullv", "num"):  # never str(None) == "None"
        with pytest.raises(ConfigError, match="is not a string"):
            provider.get(name)


def test_vault_nested_auth_mounts_sign_in_and_dot_segments_are_refused(vault, monkeypatch):
    vault.approle["role-n"] = "sid" + "-n"
    monkeypatch.setenv("VAULT_SECRET_ID", "sid-n")
    nested = _settings(vault, auth="approle", role_id="role-n", auth_mount="team-a/approle")
    assert make("secrets", nested).get("db") == VALUE
    with pytest.raises(ValueError, match="segments"):
        _settings(vault, auth="approle", role_id="r", auth_mount="team/../approle")


def test_vault_settings_need_tls_and_their_auth_fields(vault):
    remote_http = "http://" + "vault.example:8200"
    for bad in (
        {"address": remote_http},
        {"address": vault.address, "auth": "approle"},
        {"address": vault.address, "auth": "kubernetes"},
        {"address": vault.address, "path_prefix": "../"},
    ):
        with pytest.raises(ValueError):
            VaultSettings(kind="vault", **bad)
    provider = make("secrets", VaultSettings(kind="vault", address="https://vault.example"))
    assert provider._context.verify_mode == ssl.CERT_REQUIRED and provider._context.check_hostname


# --- azure_key_vault / gcp_secret_manager --------------------------------------------------------------


def test_azure_builds_with_default_azure_credential_and_refuses_bad_names():
    from azure.identity import DefaultAzureCredential

    provider = make("secrets", AzureKeyVaultSettings(kind="azure_key_vault", vault_url=VAULT_URL))
    assert isinstance(provider._client._client._config.credential, DefaultAzureCredential)
    with pytest.raises(ConfigError, match="letters, digits and '-'"):
        provider.get("pg_dsn")
    with pytest.raises(ValueError):
        AzureKeyVaultSettings(kind="azure_key_vault", vault_url="http://kv.example")


def test_gcp_without_application_default_credentials_is_a_config_error(monkeypatch):
    import google.auth
    from google.auth.exceptions import DefaultCredentialsError

    def no_adc(*a, **k):
        raise DefaultCredentialsError("none")

    monkeypatch.setattr(google.auth, "default", no_adc)
    with pytest.raises(ConfigError, match="no Application Default Credentials"):
        make("secrets", GcpSecretManagerSettings(kind="gcp_secret_manager", project_id=PROJECT))


# --- mounted_file -------------------------------------------------------------------------------------


def test_azure_client_timeouts_and_retries_are_bounded():
    provider = make("secrets", AzureKeyVaultSettings(kind="azure_key_vault", vault_url=VAULT_URL))
    pipeline = (
        provider._client._client._client._pipeline
    )  # SecretClient -> generated -> PipelineClient
    config = pipeline._transport.connection_config
    retry = next(p for p in pipeline._impl_policies if type(p).__name__ == "RetryPolicy")
    assert (config.timeout, config.read_timeout, retry.total_retries) == (3, 5, 2)


def test_an_unreadable_mounted_file_is_a_config_error(tmp_path, monkeypatch):
    root = tmp_path / "mounted"
    root.mkdir()
    write_secret_file(root, "db", VALUE)

    def denied(*a, **k):
        raise PermissionError("denied")

    monkeypatch.setattr(Path, "read_text", denied)
    with pytest.raises(ConfigError, match="cannot be read \\(PermissionError\\)"):
        MountedFileProvider(root).get("db")


def test_mounted_files_drop_one_newline_and_refuse_escapes_and_empties(tmp_path):
    root = tmp_path / "mounted"
    root.mkdir()
    write_secret_file(root, "db", VALUE)
    write_secret_file(root, "empty", "")
    (tmp_path / "outside").write_text(VALUE, encoding="utf-8")
    provider = make("secrets", MountedFileSettings(kind="mounted_file", dir=root))
    assert provider.get("db") == VALUE
    for bad in ("../outside", str(tmp_path / "outside"), "missing"):
        with pytest.raises(ConfigError):
            provider.get(bad)
    with pytest.raises(ConfigError, match="is empty"):
        provider.get("empty")
    with pytest.raises(ConfigError, match="not a folder"):
        make("secrets", MountedFileSettings(kind="mounted_file", dir=tmp_path / "nope"))


@pytest.mark.skipif(not POSIX, reason="Windows has no world-readable bit; its folder ACL decides")
def test_mounted_files_readable_by_every_user_or_linked_out_are_refused(tmp_path):
    root = tmp_path / "mounted"
    root.mkdir()
    write_secret_file(root, "db", VALUE)
    (root / "db").chmod(0o644)  # Kubernetes' default defaultMode
    (tmp_path / "outside").write_text(VALUE, encoding="utf-8")
    (root / "link").symlink_to(tmp_path / "outside")
    provider = MountedFileProvider(root)
    with pytest.raises(ConfigError, match="readable by every user"):
        provider.get("db")
    with pytest.raises(ConfigError, match="escapes"):
        provider.get("link")


def test_mounted_files_follow_kubernetes_data_links(tmp_path):
    """Kubernetes mounts <dir>/<name> -> ..data/<name> -> ..<timestamp>/<name>, all inside the folder."""
    root = tmp_path / "mounted"
    real = root / "..2026_10_31"
    real.mkdir(parents=True)
    write_secret_file(real, "db", VALUE)
    try:
        (root / "..data").symlink_to(real.name, target_is_directory=True)
        (root / "db").symlink_to(Path("..data") / "db")
    except OSError:
        pytest.skip("this machine may not create symlinks")
    assert MountedFileProvider(root).get("db") == VALUE


# --- every extra: a missing package gives the install hint --------------------------------------------


@pytest.mark.parametrize(
    "settings,package,extra",
    [
        (AwsSecretsManagerSettings(kind="aws_secrets_manager", region=REGION), "boto3", "aws"),
        (AzureKeyVaultSettings(kind="azure_key_vault", vault_url=VAULT_URL), "azure", "azure"),
        (GcpSecretManagerSettings(kind="gcp_secret_manager", project_id=PROJECT), "google", "gcp"),
    ],
)
def test_a_missing_extra_names_the_pip_install(monkeypatch, settings, package, extra):
    module = {"aws": "secrets_aws", "azure": "secrets_azure", "gcp": "secrets_gcp"}[extra]
    monkeypatch.delitem(sys.modules, f"hadavin_sdk.actions.{module}", raising=False)
    for name in [m for m in sys.modules if m == package or m.startswith(package + ".")]:
        monkeypatch.delitem(sys.modules, name)
    monkeypatch.setitem(sys.modules, package, None)  # import fails as if not installed
    with pytest.raises(ConfigError, match=rf"pip install hadavin-sdk\[{extra}\]"):
        make("secrets", settings)


def test_every_secrets_module_is_a_secret_holder():
    actions = Path(__file__).resolve().parents[1] / "src" / "hadavin_sdk" / "actions"
    modules = {f"hadavin_sdk.actions.{p.stem}" for p in actions.glob("secrets*.py")}
    assert modules <= SECRET_HOLDERS
