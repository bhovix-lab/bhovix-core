"""`azure_key_vault_key` signer (`pip install hadavin-sdk[azure]`): an EC P-256 key in Azure Key Vault or
Managed HSM, ES256. Key Vault has no Ed25519 (its EC curves are P-256, P-384, P-521 and P-256K; checked
2026-10-31), so this signer's `alg` is `ecdsa-p256`: the signature is raw r || s over SHA-256 of the message,
and `public_key()` is the uncompressed point; both verify locally with `cryptography`.

`key_id` names one key **version** (`https://<vault>.vault.azure.net/keys/<name>/<version>`): checkpoints
signed before a rotation must still verify with the key that signed them. Signs in with
`DefaultAzureCredential` (managed or workload identity).
"""

from __future__ import annotations

import hashlib
from typing import Any, Literal

import azure.keyvault.keys as azure_keys

# The extra: a missing install fails at start-up with the hint (backends.make).
from azure.identity import DefaultAzureCredential
from azure.keyvault.keys.crypto import CryptographyClient, SignatureAlgorithm

from hadavin_sdk.audit.signer import probe
from hadavin_sdk.errors import ConfigError


class AzureKeyVaultSigner:
    alg: Literal["ecdsa-p256"] = "ecdsa-p256"

    def __init__(self, key_id: str, crypto: Any, keys: Any) -> None:
        self.key_id, self._crypto, self._keys = key_id, crypto, keys
        self._public: bytes | None = None

    def sign(self, message: bytes) -> bytes:
        digest = hashlib.sha256(message).digest()
        return self._crypto.sign(SignatureAlgorithm.es256, digest).signature

    def public_key(self) -> bytes:
        if self._public is None:  # a key version's public half never changes
            ident = azure_keys.KeyVaultKeyIdentifier(self.key_id)
            jwk = self._keys.get_key(ident.name, ident.version).key
            kty, crv = (getattr(v, "value", v) for v in (jwk.kty, jwk.crv))
            if kty not in {"EC", "EC-HSM"} or crv != "P-256":
                raise ConfigError(
                    f"signer azure_key_vault_key: {self.key_id} is not an EC P-256 key"
                )
            self._public = b"\x04" + jwk.x.rjust(32, b"\0") + jwk.y.rjust(32, b"\0")
        return self._public


def build(settings, deps) -> AzureKeyVaultSigner:
    ident = azure_keys.KeyVaultKeyIdentifier(settings.key_id)
    if not ident.version:
        raise ConfigError("signer azure_key_vault_key: key_id must name a key version")
    credential = DefaultAzureCredential()
    signer = AzureKeyVaultSigner(
        settings.key_id,
        CryptographyClient(settings.key_id, credential),
        azure_keys.KeyClient(ident.vault_url, credential),
    )
    return probe(signer, "signer azure_key_vault_key")
