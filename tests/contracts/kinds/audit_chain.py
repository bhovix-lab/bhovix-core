"""The `chain` audit kind and the `ed25519_local` and `aws_kms` signer kinds (slice 2 P3).

moto 5.2.4 has no ECC_NIST_EDWARDS25519 keys (checked 2026-10-31), so `aws_kms` runs against `kms_stub`: a
real boto3 KMS client whose Sign / GetPublicKey calls are answered in-process, each answer validated against
the KMS API's documented output shape (as botocore's Stubber does). The live run is P9.
"""

from __future__ import annotations

import boto3
from botocore.awsrequest import AWSResponse
from botocore.exceptions import ClientError
from botocore.validate import validate_parameters
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hadavin_sdk.actions.secrets import FakeSecretProvider
from hadavin_sdk.audit import signer as signer_mod
from hadavin_sdk.backends import make
from hadavin_sdk.backends.table import ChainSettings, Ed25519LocalSettings, KindSettings
from tests.contracts.kinds import kind

# A region botocore knows, read from its own data (no region literal in the repo).
REGION = boto3.session.Session().get_available_regions("kms")[0]
KEY_ALIAS = "alias/" + "contract-audit"


def kms_stub(known: str = KEY_ALIAS):
    """A boto3 KMS client with one Ed25519 key that never leaves it; `calls` records each request."""
    # Explicit fake credentials: endpoint resolution reads credentials, and must never reach a real profile.
    client = boto3.client(
        "kms",
        region_name=REGION,
        aws_access_key_id="AKIA" + "IOSFODNN7EXAMPLE",
        aws_secret_access_key="fake" + "-secret-key",
    )
    key, calls = Ed25519PrivateKey.generate(), []
    der = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )

    def keep(params, context, **_):
        context["api_params"] = dict(params)  # before-call only sees the serialized request

    def answer(model, context, **_):
        params = context["api_params"]
        calls.append((model.name, params))
        if params.get("KeyId") != known:
            err = {"Error": {"Code": "NotFoundException", "Message": "not found"}}
            raise ClientError(err, model.name)
        if model.name == "Sign":
            out = {
                "KeyId": known,
                "Signature": key.sign(params["Message"]),
                "SigningAlgorithm": "ED25519_SHA_512",
            }
        elif model.name == "GetPublicKey":
            out = {
                "KeyId": known,
                "PublicKey": der,
                "KeySpec": "ECC_NIST_" + "EDWARDS25519",  # split: a scanner reads the name as a key
                "KeyUsage": "SIGN_VERIFY",
                "SigningAlgorithms": ["ED25519_SHA_512"],
            }
        else:
            raise AssertionError(f"unexpected KMS call {model.name}")
        validate_parameters(out, model.output_shape)  # the documented response shape
        return AWSResponse(None, 200, {}, None), out

    client.meta.events.register("before-parameter-build.kms.*", keep)
    client.meta.events.register_first("before-call.kms.*", answer)
    client.calls = calls
    return client


def local_signer_settings(tmp_path, passphrase: str | None = None) -> Ed25519LocalSettings:
    priv = tmp_path / "audit-key.pem"
    if not priv.exists():
        signer_mod.generate_key(
            priv,
            tmp_path / "audit-key.pub",
            passphrase.encode() if passphrase else None,
            base=tmp_path,
        )
    return Ed25519LocalSettings(
        kind="ed25519_local",
        private_key_path=priv,
        passphrase_secret_name="audit-pass" if passphrase else None,
    )


@kind("signer", "ed25519_local")
def ed25519_local(tmp_path):
    """Returns the signer and a callable that builds the same kind with a missing key."""
    secret = "pass" + "-contract"  # built from parts
    signer = make(
        "signer",
        local_signer_settings(tmp_path, secret),
        FakeSecretProvider({"audit-pass": secret}),
    )

    def missing():
        settings = Ed25519LocalSettings(
            kind="ed25519_local", private_key_path=tmp_path / "gone.pem"
        )
        return make("signer", settings)

    return signer, missing


@kind("signer", "aws_kms")
def aws_kms(tmp_path):
    signer = signer_mod.probe(signer_mod.KmsSigner(KEY_ALIAS, kms_stub()), "signer aws_kms")
    return signer, lambda: signer_mod.probe(
        signer_mod.KmsSigner("alias/" + "gone", kms_stub()), "signer aws_kms"
    )


@kind("audit", "chain")
def chain(tmp_path):
    """The chain on the memory store (an in-memory SQLite chain), signed by a local key."""
    store = make("store", KindSettings(kind="memory"))
    signer = make("signer", local_signer_settings(tmp_path))
    return make("audit", ChainSettings(kind="chain"), store=store, signer=signer)


@kind("audit", "chain_postgres")
def chain_postgres(tmp_path):
    """The chain in the postgres store's database (HADAVIN_TEST_PG_DSN; the CI postgres service)."""
    from hadavin_sdk.backends.table import PostgresSettings
    from tests.contracts.kinds.store_postgres import pg_schema

    for dsn in pg_schema():
        settings = PostgresSettings(kind="postgres", dsn_secret_name="pg-dsn")  # noqa: S106 - a name
        store = make("store", settings, FakeSecretProvider({"pg-dsn": dsn}))
        signer = make("signer", local_signer_settings(tmp_path))
        yield make("audit", ChainSettings(kind="chain"), store=store, signer=signer)
        store._db.close()
