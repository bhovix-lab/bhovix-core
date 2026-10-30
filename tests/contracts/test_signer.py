"""Signer suite (design 6, 12.6 P3) over every registered signer kind: verify with the public key alone."""

import pytest

from hadavin_sdk.audit.signer import verify_signature
from hadavin_sdk.errors import ConfigError
from tests.contracts.kinds import KINDS


@pytest.fixture(params=sorted(KINDS["signer"]))
def signer_and_missing(request, tmp_path):
    return KINDS["signer"][request.param](tmp_path)


def test_signature_verifies_with_the_public_key_and_a_flipped_bit_fails(signer_and_missing):
    signer, _ = signer_and_missing
    message = b"hadavin-audit:5:" + b"ab" * 32
    sig = signer.sign(message)
    assert signer.alg == "ed25519" and len(sig) == 64 and len(signer.public_key()) == 32
    assert verify_signature(signer.public_key(), sig, message)
    flipped = bytes([sig[0] ^ 1]) + sig[1:]
    assert not verify_signature(signer.public_key(), flipped, message)
    assert not verify_signature(signer.public_key(), sig, message + b"x")


def test_key_id_is_stable(signer_and_missing):
    signer, _ = signer_and_missing
    first = signer.key_id
    signer.sign(b"m")
    assert signer.key_id == first and first


def test_a_missing_key_is_a_config_error(signer_and_missing):
    _, missing = signer_and_missing
    with pytest.raises(ConfigError):
        missing()
