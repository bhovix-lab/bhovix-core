"""`vault_transit` signer: an `ed25519` key in the Transit engine of HashiCorp Vault or OpenBao.

Works on any cloud or none, through Vault's HTTP API (the same client and sign-in as the `vault` secrets kind:
token, AppRole or Kubernetes; TLS verified; never follows redirects). Vault signs; the private key never leaves
it. The signature is plain Ed25519 over the raw message, so it verifies locally like every other signer.

`key_version` pins one version: `sign` asks for it explicitly, and `public_key()` reads that version's key, so
checkpoints signed before a `rotate` still verify with the key that signed them.
"""

from __future__ import annotations

import base64
import threading
from typing import Any, Literal

from hadavin_sdk.actions.secrets_vault import VaultError, connect
from hadavin_sdk.audit.signer import probe
from hadavin_sdk.errors import ConfigError


class VaultTransitSigner:
    alg: Literal["ed25519"] = "ed25519"

    def __init__(self, client: Any, mount: str, key_name: str, key_version: int) -> None:
        self._vault = client
        self.mount = mount
        self.key_name = key_name
        self.key_version = key_version
        self.key_id = f"vault-transit:{mount}/{key_name}:v{key_version}"
        self._lock = threading.Lock()  # the client's token refresh is not thread-safe by itself
        self._public: bytes | None = None

    def _call(self, method: str, path: str, body: dict | None = None) -> dict:
        with self._lock:
            status, answer = self._vault.authed(method, f"{self.mount}/{path}", body)
        if status != 200:
            raise VaultError(
                f"transit {path.split('/')[0]} {self.key_name}: Vault answered {status}"
            )
        data = answer.get("data")
        if not isinstance(data, dict):
            raise VaultError("Vault answered with an unexpected JSON shape")
        return data

    def sign(self, message: bytes) -> bytes:
        body = {"input": base64.b64encode(message).decode(), "key_version": self.key_version}
        signature = self._call("POST", f"sign/{self.key_name}", body).get("signature")
        prefix = f"vault:v{self.key_version}:"
        if not isinstance(signature, str) or not signature.startswith(prefix):
            raise VaultError(
                f"transit sign {self.key_name}: not signed by version {self.key_version}"
            )
        return base64.b64decode(signature.removeprefix(prefix))

    def public_key(self) -> bytes:
        if self._public is None:  # a key version's public half never changes
            data = self._call("GET", f"keys/{self.key_name}")
            version = (data.get("keys") or {}).get(str(self.key_version))
            if data.get("type") != "ed25519" or not isinstance(version, dict):
                raise ConfigError(
                    f"signer vault_transit: {self.key_name} v{self.key_version} is not an ed25519 key"
                )
            raw = base64.b64decode(version.get("public_key") or "")
            if len(raw) != 32:
                raise ConfigError(
                    f"signer vault_transit: {self.key_name} has no ed25519 public key"
                )
            self._public = raw
        return self._public


def build(settings, deps) -> VaultTransitSigner:
    version = settings.key_version
    client = connect(settings, ttl_s=0)
    signer = VaultTransitSigner(client, settings.transit_mount, settings.key_name, version)
    return probe(signer, "signer vault_transit")
