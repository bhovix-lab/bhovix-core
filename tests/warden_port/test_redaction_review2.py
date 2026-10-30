"""Ported from WARDEN tests/test_redaction_review2.py (main a1e76cbf, veerarakesh56/warden). Kept 5 tests; dropped 16 that need WARDEN-only modules or unported gate policy (listed in the PR).

Redaction against the second independent review's probes (2026-09-30, area B).

Each case is the reviewer's own string (review2/B: t22b.py, t_sweep_fp.py, t_order.py, t_labels.py,
t_blob.py, t_mcp.py). Fake secrets are built by concatenation, so the publish guard never sees a
literal that looks real."""

from __future__ import annotations

import pytest

from hadavin_sdk.guard.redact import redact

S = "5ecret"
LEAKS = [
    ("wh" + "sec_C2FVsBQIhrscChlQIMV+b5sSYspob7oD", "b5sSYspob7oD"),
    ("Webhook-Secret: wh" + "sec_Zm9vYmFyYmF6cXV4Zm9vYmFy/Zm9vYmFy+YmF6", "YmF6"),
    ('["--db-password", "Dbpw' + S + '"]', "Dbpw" + S),
    ('["--client-secret","Cl' + S + 'V"]', "Cl" + S + "V"),
    (
        "kubectl create secret docker-registry regcred --docker-password Dock"
        + S
        + " --docker-username ci",
        "Dock" + S,
    ),
    ("wget --http-password Wg" + S + " https://x", "Wg" + S),
    ("az login -u ci -p Az" + S + "Pw", "Az" + S + "Pw"),
    ("sqlcmd -S db -U sa -P Sq" + S + "Pw -Q 'select 1'", "Sq" + S + "Pw"),
    ("mariadb -u root -pMaria" + S, "Maria" + S),
    ("curl -uadmin:Curl" + S + " https://api", "Curl" + S),
    ("curl --user=admin:Curl" + S + " https://api", "Curl" + S),
    ("redis-cli --pass Redis" + S, "Redis" + S),
    ("REDISCLI_AUTH=Redis" + S + " redis-cli", "Redis" + S),
    ("ldapsearch -D cn=admin -w Ldap" + S, "Ldap" + S),
    ("mongosh -u admin -p Mongo" + S, "Mongo" + S),
    ("htpasswd -b users admin Ht" + S + "Pw", "Ht" + S + "Pw"),
    ("openssl enc -pass pass:Ossl" + S, "Ossl" + S),
    ("vault login s.Vt" + S + "Token123456", "Vt" + S + "Token123456"),
    ("--password\xa0Nbsp" + S, "Nbsp" + S),
]


@pytest.mark.parametrize("text, secret", LEAKS, ids=[t[:24] for t, _ in LEAKS])
def test_every_reviewed_credential_shape_is_masked(text, secret):
    out = redact(text).text
    assert secret not in out, out
    assert secret[:6] not in out or "<" in out, out


FALSE_POSITIVES = [
    "error: --token not set; user not found, service not ready",
    "the --secret flag is deprecated; use feature flag instead",
    "Missing --password argument (argument list too short)",
    "docker build --secret id=npmrc,src=.npmrc .",
    "usage: app --password PASSWORD --token TOKEN",
]


@pytest.mark.parametrize("text", FALSE_POSITIVES)
def test_words_after_a_credential_flag_are_not_taken_for_its_value(text):
    assert redact(text).text == text


def test_a_credential_is_still_masked_in_every_line():
    from hadavin_sdk.guard.redact import redact_many

    secret = "hunter" + "2" + "Qx9" + "hunter" + "7"
    out, _ = redact_many(
        ["login pass" + f"word={secret} rejected", f"retrying with {secret} in 5s"]
    )
    assert all(secret not in line for line in out), out


def test_redacting_many_lines_stays_fast():
    """Third review (2026-09-30): 300 log lines took 68 s (122 s measured here) once there were more
    found values than Python's regex cache holds; the same lines now take under a second."""
    import time

    from hadavin_sdk.guard.redact import redact_many

    lines = []
    for i in range(300):
        ip = f"10.{i % 250}.{i * 7 % 250}.{i * 13 % 250}"
        lines.append(
            f"checkout ERROR req={i:08x} from {ip} user=user{i}"
            + "@"
            + "example.org"
            + " pass"
            + "word="
            + "tok_"
            + f"{i:04d}"
            + "q9Z" * 8
            + " status=500"
        )
    start = time.perf_counter()
    out, mapping = redact_many(lines)
    assert time.perf_counter() - start < 15, "redaction cost regressed"
    assert len(mapping) > 512
    assert not any("q9Zq9Z" in line for line in out)


def _values(n):
    """Secret-shaped values built from parts (no real-looking literal in the repo)."""
    return {
        "base64": "BwgJCgsMDQ4P" + "EBESExQVFg==",
        "passphrase": "tundra-gallop-" + "nimbus-quartz",
        "letters": "ujzPqWmAxtRb" + "LkcVnHyGsDfe",
    }[n]


def _lines(n, k):
    ip = lambda i, j: f"10.{(i * 7 + j) % 250}.{(i + j * 13) % 250}.{i * j % 250}"
    uid = lambda i, j: f"{i:08x}-{j:04x}-4{i % 4096:03x}-a{j % 4096:03x}-{i * 1000 + j:012x}"
    return [
        " ".join(f"from {ip(i, j)} req={uid(i, j)} pass" + f"word=s3cr{i}x{j}Q" for j in range(k))
        for i in range(n)
    ]


def _best_time(lines, runs=2):
    import time

    from hadavin_sdk.guard.redact import redact_many

    best = float("inf")
    for _ in range(runs):
        start = time.perf_counter()
        redact_many(lines)
        best = min(best, time.perf_counter() - start)
    return best


def test_a_shorter_secret_starting_where_a_longer_value_starts_is_still_masked():
    """Fifth review (2026-10-01): the finder reports only the longest value at a position. Here the longer
    value is an identifier (`<secret>99`, found as a user id) that is not standalone inside `Q<secret>99`,
    so it is not replaced - and the secret inside it was never checked, and stayed in clear."""
    from hadavin_sdk.guard.redact import redact_many

    secret = "Tr0ub4" + "dor"
    out, _ = redact_many(
        [
            f"db password={secret} rejected",
            f"lookup user_id={secret}99 ok",
            f"cache miss for key Q{secret}99",
        ]
    )
    assert all(secret not in line for line in out), out
