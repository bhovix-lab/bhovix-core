"""Cloud-neutral signer and anchor kinds (slice 2 P3b). Signers register under `signer` (the Signer suite);
anchors under `anchor` (tests/contracts/test_anchor.py), each returning a fresh anchor (a generator may clean
up after it).

* `vault_transit`: a real `vault server -dev` when HADAVIN_TEST_VAULT_ADDR is set (CI), else the local fake.
* `azure_key_vault_key`, `gcp_kms`, `azure_immutable_blob`, `gcs_retention_lock`: the real SDK clients over the
  in-process HTTP fakes in tests/contracts/http_fake.py.
* `s3_object_lock`: moto (an Object Lock bucket).
"""

from __future__ import annotations

import uuid

import boto3
from moto import mock_aws

from hadavin_sdk.actions.secrets_vault import VaultProvider
from hadavin_sdk.audit.anchor_azure import AzureBlobAnchor
from hadavin_sdk.audit.anchor_gcs import GcsAnchor
from hadavin_sdk.audit.anchor_s3 import S3Anchor
from hadavin_sdk.audit.signer import probe
from hadavin_sdk.audit.signer_azure import AzureKeyVaultSigner
from hadavin_sdk.audit.signer_gcp import GcpKmsSigner
from hadavin_sdk.audit.signer_vault import VaultTransitSigner
from tests.contracts.http_fake import (
    azure_container,
    azure_key_clients,
    gcp_kms_client,
    gcs_bucket,
)
from tests.contracts.kinds import kind
from tests.contracts.kinds.audit_chain import REGION
from tests.contracts.kinds.secrets_neutral import vault_target

AZURE_KEY = "https://contract-kv.vault.azure.net/keys/audit/0123456789abcdef"
GCP_KEY = "/".join(
    ["projects", "contract", "locations", "global", "keyRings", "audit"]
    + ["cryptoKeys", "chain", "cryptoKeyVersions", "1"]
)


def transit_key() -> tuple[VaultProvider, str]:
    """A fresh ed25519 Transit key (the engine is enabled first, as an operator would)."""
    address, token = vault_target()
    client = VaultProvider(address, lambda p: token, ttl_s=0)
    client.authed("POST", "sys/mounts/transit", {"type": "transit"})  # 204, or 400 once enabled
    name = f"audit-{uuid.uuid4().hex[:10]}"
    status, _ = client.authed("POST", f"transit/keys/{name}", {"type": "ed25519"})
    assert status in (200, 204), status
    return client, name


@kind("signer", "vault_transit")
def vault_transit(tmp_path):
    client, name = transit_key()
    signer = probe(VaultTransitSigner(client, "transit", name, 1), "signer vault_transit")
    return signer, lambda: probe(
        VaultTransitSigner(client, "transit", "gone-" + name, 1), "signer vault_transit"
    )


@kind("signer", "azure_key_vault_key")
def azure_key_vault_key(tmp_path):
    signer = probe(AzureKeyVaultSigner(AZURE_KEY, *azure_key_clients(AZURE_KEY)), "signer azure")
    gone = AZURE_KEY.replace("/audit/", "/gone/")
    crypto, keys = azure_key_clients(AZURE_KEY)  # holds `audit` only: `gone` is not found
    return signer, lambda: probe(AzureKeyVaultSigner(gone, crypto, keys), "signer azure")


@kind("signer", "gcp_kms")
def gcp_kms(tmp_path):
    signer = probe(GcpKmsSigner(GCP_KEY, gcp_kms_client(GCP_KEY)), "signer gcp_kms")
    gone = GCP_KEY.replace("/chain/", "/gone/")
    return signer, lambda: probe(GcpKmsSigner(gone, gcp_kms_client(GCP_KEY)), "signer gcp_kms")


@kind("anchor", "s3_object_lock")
def s3_object_lock(tmp_path):
    with mock_aws():
        s3 = boto3.client("s3", region_name=REGION)
        bucket = "anchors-" + uuid.uuid4().hex[:8]
        s3.create_bucket(
            Bucket=bucket,
            ObjectLockEnabledForBucket=True,
            CreateBucketConfiguration={"LocationConstraint": REGION},
        )
        yield S3Anchor(bucket, s3)


@kind("anchor", "azure_immutable_blob")
def azure_immutable_blob(tmp_path):
    return AzureBlobAnchor(azure_container("anchors"))


@kind("anchor", "gcs_retention_lock")
def gcs_retention_lock(tmp_path):
    return GcsAnchor(gcs_bucket("contract-anchors"))
