"""The cloud-neutral secrets kinds (slice 2 P4b): `vault`, `azure_key_vault`, `gcp_secret_manager`,
`mounted_file`. Each registers under `secrets` (the shared suite) and `secrets_ttl` (provider, change, advance,
ttl_s), like `secrets_cloud.py`.

* `vault`: a real `vault server -dev` when HADAVIN_TEST_VAULT_ADDR is set (the CI service container), else the
  local fake in `tests/contracts/vault_fake.py`.
* `azure_key_vault`, `gcp_secret_manager`: the real SDK clients over `tests/contracts/http_fake.py`.
"""

from __future__ import annotations

import os
import uuid

from hadavin_sdk.actions.secrets_azure import AzureKeyVaultProvider
from hadavin_sdk.actions.secrets_file import MountedFileProvider
from hadavin_sdk.actions.secrets_gcp import GcpSecretManagerProvider
from hadavin_sdk.actions.secrets_vault import VaultProvider
from tests.contracts.http_fake import azure_secret_client, gcp_secret_client
from tests.contracts.kinds import kind
from tests.contracts.vault_fake import ROOT, fake_vault

TTL_S = 300
VAULT_URL = (
    "https://contract-kv.vault.azure.net"  # test fixture host; every call is answered in-process
)
PROJECT = "contract-project"


def _clock():
    now = [0.0]

    def advance(seconds):
        now[0] += seconds

    return (lambda: now[0]), advance


# --- vault ---------------------------------------------------------------------------------------------


def vault_target() -> tuple[str, str]:
    """(address, admin token): the CI dev server, or the local fake."""
    if address := os.environ.get("HADAVIN_TEST_VAULT_ADDR"):
        return address, os.environ.get("HADAVIN_TEST_VAULT_TOKEN", ROOT)
    return fake_vault().address, ROOT


def _vault(seed):
    address, token = vault_target()
    clock, advance = _clock()
    provider = VaultProvider(
        address,
        lambda p: token,
        path_prefix=f"t{uuid.uuid4().hex[:12]}/",
        ttl_s=TTL_S,
        clock=clock,
    )

    def write(name, value):
        path = f"{provider.mount}/data/{provider.path_prefix}{name}"
        status, _ = provider.call("POST", path, {"data": {"value": value}}, token=token)
        assert status in (200, 204), status

    for name, value in seed.items():
        write(name, value)
    return provider, write, advance


@kind("secrets", "vault")
def vault(tmp_path, seed):
    return _vault(seed)[0]


@kind("secrets_ttl", "vault")
def vault_ttl(tmp_path, seed):
    return (*_vault(seed), TTL_S)


# --- azure_key_vault / gcp_secret_manager ----------------------------------------------------------------


def _azure(seed):
    values, (clock, advance) = dict(seed), _clock()
    provider = AzureKeyVaultProvider(azure_secret_client(VAULT_URL, values), TTL_S, clock)
    return provider, values.__setitem__, advance


@kind("secrets", "azure_key_vault")
def azure_key_vault(tmp_path, seed):
    return _azure(seed)[0]


@kind("secrets_ttl", "azure_key_vault")
def azure_key_vault_ttl(tmp_path, seed):
    return (*_azure(seed), TTL_S)


def _gcp(seed):
    values, (clock, advance) = dict(seed), _clock()
    provider = GcpSecretManagerProvider(gcp_secret_client(values), PROJECT, TTL_S, clock)
    return provider, values.__setitem__, advance


@kind("secrets", "gcp_secret_manager")
def gcp_secret_manager(tmp_path, seed):
    return _gcp(seed)[0]


@kind("secrets_ttl", "gcp_secret_manager")
def gcp_secret_manager_ttl(tmp_path, seed):
    return (*_gcp(seed), TTL_S)


# --- mounted_file -----------------------------------------------------------------------------------------


def write_secret_file(root, name, value):
    """As a Kubernetes Secret volume with defaultMode 0400 would leave it."""
    path = root / name
    if path.exists():
        path.chmod(0o600)
    path.write_text(value + "\n", encoding="utf-8")
    path.chmod(0o400)


def _mounted(tmp_path, seed):
    root = tmp_path / "mounted"
    root.mkdir(exist_ok=True)
    for name, value in seed.items():
        write_secret_file(root, name, value)
    clock, advance = _clock()
    provider = MountedFileProvider(root, TTL_S, clock)
    return provider, lambda n, v: write_secret_file(root, n, v), advance


@kind("secrets", "mounted_file")
def mounted_file(tmp_path, seed):
    return _mounted(tmp_path, seed)[0]


@kind("secrets_ttl", "mounted_file")
def mounted_file_ttl(tmp_path, seed):
    return (*_mounted(tmp_path, seed), TTL_S)
