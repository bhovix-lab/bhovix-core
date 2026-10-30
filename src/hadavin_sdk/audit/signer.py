"""Checkpoint signers (OD-4): Ed25519 only, so an auditor verifies a checkpoint with the public key alone.

Ported from WARDEN `audit.py` (main c78d7709): `KmsSigner` and the key helpers (`key_path`, `generate_key`,
`load_private_key`, `load_public_key`). Edits: each signer has a stable `key_id` and `alg`, and `public_key()`
returns the raw 32 bytes. Needs `cryptography` (`pip install hadavin-sdk[signer]`; `aws_kms` also needs `[aws]`).
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any, Literal, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from hadavin_sdk.errors import ConfigError

_RAW = (serialization.Encoding.Raw, serialization.PublicFormat.Raw)


class Signer(Protocol):
    key_id: str
    alg: Literal["ed25519"]

    def sign(self, message: bytes) -> bytes:
        """A 64-byte Ed25519 signature over the raw message."""
        ...

    def public_key(self) -> bytes:
        """The raw 32-byte public key."""
        ...


def verify_signature(public_key: bytes, signature: bytes, message: bytes) -> bool:
    """Local check with the public key alone: what an auditor runs."""
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
    except (InvalidSignature, ValueError):
        return False
    return True


class LocalSigner:
    """An Ed25519 key in a PEM file (dev and pilot; refused in prod by the environment table)."""

    alg: Literal["ed25519"] = "ed25519"

    def __init__(self, key: ed25519.Ed25519PrivateKey) -> None:
        self._key = key
        self.key_id = "ed25519:" + hashlib.sha256(self.public_key()).hexdigest()[:16]

    def sign(self, message: bytes) -> bytes:
        return self._key.sign(message)

    def public_key(self) -> bytes:
        return self._key.public_key().public_bytes(*_RAW)


class KmsSigner:
    """An Ed25519 key held by AWS KMS: it signs, and nobody (Hadavin included) can export it, so a copy of the
    database and the code is not enough to sign a rewritten history. ECC_NIST_EDWARDS25519 keys sign with
    ED25519_SHA_512 over the RAW message; the signature is plain Ed25519."""

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


def probe(signer: Signer, label: str) -> Signer:
    """Start-up: sign a test message and verify it, so an unreachable or wrong key fails before the first run."""
    message = b"hadavin-signer-probe"
    try:
        ok = verify_signature(signer.public_key(), signer.sign(message), message)
    except ConfigError:
        raise
    except Exception as exc:
        raise ConfigError(f"{label}: cannot sign at start-up ({exc.__class__.__name__})") from exc
    if not ok:
        raise ConfigError(f"{label}: the key's signature does not verify with its public key")
    return signer


# --------------------------------------------------------------------------- table factories


def build_local(settings, deps) -> LocalSigner:
    path = Path(settings.private_key_path)
    if not path.is_file():
        raise ConfigError(f"signer ed25519_local: no key file at {path}")
    name = settings.passphrase_secret_name
    passphrase = deps.resolve(name).encode("utf-8") if name else None
    try:
        key = load_private_key(path, passphrase)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"signer ed25519_local: cannot load {path} ({exc})") from None
    return probe(LocalSigner(key), "signer ed25519_local")


def build_kms(settings, deps) -> KmsSigner:
    import boto3  # the `aws` extra
    from botocore.config import Config

    # Checkpoints are signed inline every N audit rows: bounded, not botocore's 60 s defaults.
    config = Config(connect_timeout=3, read_timeout=5, retries={"total_max_attempts": 2})
    client = boto3.client("kms", region_name=settings.region, config=config)
    return probe(KmsSigner(settings.key_id, client), "signer aws_kms")


# --------------------------------------------------------------------------- keys

# Key files are written inside one folder only: a path from a command line must never reach `~/.bashrc`, a
# synced folder, or a file through `..` or a symlink. The folder is HADAVIN_KEY_DIR, or ~/.hadavin.
KEY_DIR_ENV = "HADAVIN_KEY_DIR"


def key_dir() -> Path:
    return Path(os.environ.get(KEY_DIR_ENV) or Path.home() / ".hadavin").expanduser()


def key_path(path: Path, base: Path | None = None) -> Path:
    """The real location of `path` when it lies inside `base` (default: the key folder, created 0700 if
    missing); else ValueError. The file itself must not be a symlink, and its folder must already exist."""
    folder = (base or key_dir()).expanduser()
    folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    folder = folder.resolve(strict=True)
    target = Path(path).expanduser()
    if target.is_symlink():
        raise ValueError(f"{path} is a symlink: a key file is never used through one")
    real = target.parent.resolve(strict=True) / target.name
    if not real.is_relative_to(folder) or real == folder:
        raise ValueError(
            f"{path} is outside {folder}: key files are kept only there "
            f"(set {KEY_DIR_ENV} to choose another folder)"
        )
    return real


def _create(real: Path, data: bytes, mode: int) -> None:
    """Create `real` holding `data`, never over an existing file; a file this call could not fill is removed."""
    fd = os.open(real, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0), mode)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
    except BaseException:
        real.unlink(missing_ok=True)
        raise


def generate_key(
    private_path: Path,
    public_path: Path,
    passphrase: bytes | None = None,
    base: Path | None = None,
) -> None:
    """A new Ed25519 pair, both files inside `base` (default: the key folder), neither written over an existing
    file. The private key is created 0600 (POSIX; on Windows the profile folder's ACL keeps others out)."""
    public_real = key_path(public_path, base)
    private_real = key_path(private_path, base)
    if public_real == private_real:
        raise ValueError(f"{private_path} and {public_path} are the same file: the pair needs two")
    if public_real.exists():
        raise FileExistsError(f"{public_path} exists; refusing to overwrite it")
    key = ed25519.Ed25519PrivateKey.generate()
    encryption = (
        serialization.BestAvailableEncryption(passphrase)
        if passphrase
        else serialization.NoEncryption()
    )
    pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption
    )
    _create(private_real, pem, 0o600)
    try:
        _create(
            public_real,
            key.public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            ),
            0o644,
        )
    except BaseException:
        private_real.unlink()  # no half pair
        raise


def load_private_key(path: Path, passphrase: bytes | None = None) -> ed25519.Ed25519PrivateKey:
    key = serialization.load_pem_private_key(path.read_bytes(), password=passphrase)
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise TypeError(f"{path} is not an Ed25519 private key")
    return key


def load_public_key(path: Path) -> bytes:
    """A PEM public key file as the raw 32 bytes (what `verify_signature` takes)."""
    key = serialization.load_pem_public_key(path.read_bytes())
    if not isinstance(key, ed25519.Ed25519PublicKey):
        raise TypeError(f"{path} is not an Ed25519 public key")
    return key.public_bytes(*_RAW)
