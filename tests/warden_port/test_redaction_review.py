"""Ported from WARDEN tests/test_redaction_review.py (main a1e76cbf, veerarakesh56/warden). Kept 4 tests; dropped 4 that need WARDEN-only modules or unported gate policy (listed in the PR).

The redaction cases the independent review of 2026-09-28 found (A-C-4, A-C-5, A-C-22).

Each case is a value a pattern found in one place that must not survive in another, a credential
shape that passed, or an ordinary word the first fix wrongly masked."""

from __future__ import annotations

import pytest

from hadavin_sdk.guard.redact import redact
from tests.warden_port.fakes import HUNTER2


@pytest.mark.parametrize(
    "found, elsewhere, value",
    [
        ("db_password=Tr0ub4dor", "msg=auth%20failed%20Tr0ub4dor", "Tr0ub4dor"),
        ("password=Tr0ub4dor", '{"m": "x\\nTr0ub4dor"}', "Tr0ub4dor"),
        ("token=Zq81kLm02", "Zq81kLm02Zq81kLm02", "Zq81kLm02"),
        ("secret=AbC123xyz", "raw=xAbC123xyz", "AbC123xyz"),
        ('api_key="k9Xq2"', "retrying with key k9Xq2", "k9Xq2"),
        ("postgres://app:pw123@db", "tried pw123", "pw123"),
        ("user_id=u8812", "payload for u8812", "u8812"),
        ("client 10.0.3.22 ok", "retry 10.0.3.22", "10.0.3.22"),
    ],
)
def test_a_value_found_once_is_masked_everywhere(found, elsewhere, value):
    """A-C-4: the thresholds of the first fix let each of these survive in the second line."""
    out = redact(found + "\n" + elsewhere)
    assert value not in out.text, out.text


def test_status_codes_and_common_words_are_not_rewritten():
    out = redact("user_id=500 tenant_id=prod GET /cart HTTP 500 in prod")
    assert "HTTP 500 in prod" in out.text


@pytest.mark.parametrize(
    "text, secret",
    [
        ('run --password "' + HUNTER2 + ' x" now', HUNTER2 + " x"),
        ("run --password '" + HUNTER2 + "'", HUNTER2),
        ('argv ["--password","pw4411"]', "pw4411"),
        ("redis-cli -h db -a Redis5ecret ping", "Redis5ecret"),
        ("curl -u admin:" + "Curl5" + "ecret https://x", "Curl5" + "ecret"),
        ("sshpass -p Ssh5ecret ssh host", "Ssh5ecret"),
        ("docker login -u me -p Dock5ecret reg", "Dock5ecret"),
        ("wh" + "sec_abcdef+b5sSYspob7oD/xyz", "b5sSYspob7oD"),
        ("host ec2-54-12-34-56.compute-1.amazonaws.com", "54-12-34-56"),
        ("pod 10-0-3-22.default.pod.cluster.local", "10-0-3-22"),
        (
            "-----BEGIN " + "PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC",
            "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC",
        ),
        ("Private-Lines: 2\nAAAAgQDputtybody\nAAAAsecond\nPrivate-MAC: ab", "AAAAgQDputtybody"),
    ],
)
def test_credential_shapes_that_still_passed(text, secret):
    """A-C-22, second round."""
    assert secret not in redact(text).text


@pytest.mark.parametrize(
    "text",
    [
        "aws secretsmanager get-secret-value --secret-name orders-db-creds",
        "kubelet --service-account-token-ttl 3600",
        "vault login --token-file /var/run/token",
        "retry -token refresh failed",
        "gateway --api-key-header X-Api-Key",
        "sshd --passwordless enabled",
        "run --secrets-provider aws",
    ],
)
def test_ordinary_flags_are_not_masked(text):
    """A-C-22: the first flag pattern masked resource names - `orders-db-creds` then vanished from
    the evidence and from the P14 inventory."""
    assert redact(text).text == text
