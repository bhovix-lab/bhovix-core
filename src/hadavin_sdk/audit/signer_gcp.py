"""`gcp_kms` signer (`pip install hadavin-sdk[gcp]`): an `EC_SIGN_ED25519` key in Cloud KMS. PureEdDSA signs
the raw message (Cloud KMS algorithms page, checked 2026-10-31), so the signature is plain Ed25519 and
verifies like the local and AWS keys.

`key_version` names one key **version** (`projects/<p>/locations/<l>/keyRings/<r>/cryptoKeys/<k>/
cryptoKeyVersions/<n>`): checkpoints signed before a rotation must still verify. Signs in with Application
Default Credentials (attached service account or workload identity).
"""

from __future__ import annotations

from typing import Any, Literal

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

# The extra: a missing install fails at start-up with the hint (backends.make).
from google.auth.exceptions import DefaultCredentialsError
from google.cloud import kms

from hadavin_sdk.audit.signer import probe
from hadavin_sdk.errors import ConfigError

_RAW = (serialization.Encoding.Raw, serialization.PublicFormat.Raw)
_ED25519 = kms.CryptoKeyVersion.CryptoKeyVersionAlgorithm.EC_SIGN_ED25519


class GcpKmsSigner:
    alg: Literal["ed25519"] = "ed25519"

    def __init__(self, key_version: str, client: Any) -> None:
        self.key_id, self._kms = key_version, client
        self._public: bytes | None = None

    def sign(self, message: bytes) -> bytes:
        return self._kms.asymmetric_sign(request={"name": self.key_id, "data": message}).signature

    def public_key(self) -> bytes:
        if self._public is None:  # a key version's public half never changes
            out = self._kms.get_public_key(request={"name": self.key_id})
            key = serialization.load_pem_public_key(out.pem.encode("utf-8"))
            if out.algorithm != _ED25519 or not isinstance(key, ed25519.Ed25519PublicKey):
                raise ConfigError(f"signer gcp_kms: {self.key_id} is not an EC_SIGN_ED25519 key")
            self._public = key.public_bytes(*_RAW)
        return self._public


def build(settings, deps) -> GcpKmsSigner:
    try:
        client = kms.KeyManagementServiceClient()
    except DefaultCredentialsError:
        raise ConfigError(
            "signer gcp_kms: no Application Default Credentials "
            "(attach a service account, or run gcloud auth application-default login)"
        ) from None
    return probe(GcpKmsSigner(settings.key_version, client), "signer gcp_kms")
