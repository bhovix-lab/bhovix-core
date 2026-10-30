"""`aws_kms` signer (`pip install hadavin-sdk[aws]`): an Ed25519 key held by AWS KMS.

Ported from WARDEN `audit.py` `KmsSigner` (main c78d7709). KMS signs, and nobody (Hadavin included) can export
the key, so a copy of the database and the code is not enough to sign a rewritten history.
ECC_NIST_EDWARDS25519 keys sign with ED25519_SHA_512 over the RAW message; the signature is plain Ed25519.
"""

from __future__ import annotations

from typing import Any, Literal

# The extra: a missing install fails at start-up with the hint (backends.make).
import boto3
from botocore.config import Config
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from hadavin_sdk.audit.signer import probe
from hadavin_sdk.errors import ConfigError

_RAW = (serialization.Encoding.Raw, serialization.PublicFormat.Raw)


class KmsSigner:
    alg: Literal["ed25519"] = "ed25519"

    def __init__(self, key_id: str, client: Any) -> None:
        self.key_id, self._kms = key_id, client
        self._public: bytes | None = None

    def sign(self, message: bytes) -> bytes:
        return self._kms.sign(
            KeyId=self.key_id,
            Message=message,
            MessageType="RAW",
            SigningAlgorithm="ED25519_SHA_512",
        )["Signature"]

    def public_key(self) -> bytes:
        if self._public is None:  # a key's public half never changes: one GetPublicKey per process
            der = self._kms.get_public_key(KeyId=self.key_id)["PublicKey"]
            key = serialization.load_der_public_key(der)
            if not isinstance(key, ed25519.Ed25519PublicKey):
                raise ConfigError(
                    f"signer aws_kms: {self.key_id} is not an ECC_NIST_EDWARDS25519 key"
                )
            self._public = key.public_bytes(*_RAW)
        return self._public


def build(settings, deps) -> KmsSigner:
    # Checkpoints are signed inline every N audit rows: bounded, not botocore's 60 s defaults.
    config = Config(connect_timeout=3, read_timeout=5, retries={"total_max_attempts": 2})
    client = boto3.client("kms", region_name=settings.region, config=config)
    return probe(KmsSigner(settings.key_id, client), "signer aws_kms")
