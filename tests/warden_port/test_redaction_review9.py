"""Ported from WARDEN tests/test_redaction_review9.py (main a1e76cbf, veerarakesh56/warden). Kept 3 tests; dropped 2 that need WARDEN-only modules or unported gate policy (listed in the PR).

Ninth independent review (2026-10-01), redaction: cookies in every written form, values whose start an earlier
pattern masked, tools saying "there is none", and a secret inside a compound value echoed alone elsewhere."""

from __future__ import annotations

import pytest

from hadavin_sdk.guard.redact import redact, redact_many

S = "Zq8wPx2mLk" + "Vb7YtR3nQs"
UUID = "1f2e3d4c-" + "5b6a-4789-a0b1-" + "c2d3e4f5a6b7"
COOKIES = [
    "headers=map[Accept:[*/*] Cookie:[_gh_sess=%s; theme=dark] User-Agent:[curl/8.4.0]]",
    "Set-Cookie:[_gh_sess=%s; Path=/; HttpOnly]",
    "X-Auth-Cookie: _gh_sess=%s",
    "x-original-cookie: _gh_sess=%s",
    "Cookie: '_gh_sess=%s; a=b",
    '{"http_cookie":"sid=%s; theme=dark"}',
    "HTTP_COOKIE=sid=%s",
    "'HTTP_COOKIE' => '_gh_sess=%s'",
    '{"cookie":"ab=\\"x\\"; _gh_sess=%s"}',
    "{'cookie': \"ab='x'; _gh_sess=%s\"}",
    '"set-cookie":["id=abcd; Path=/", "_gh_sess=%s; Path=/"]',
    '{"name":"Cookie","value":"_gh_sess=%s"}',
    'curl --cookie "_gh_sess=%s" https://x.example',
    "curl -b '_gh_sess=%s' https://x.example",
    "cookies={'_gh_sess': '%s'}",
    "<RequestsCookieJar[<Cookie _gh_sess=%s for x.example/>]>",
]


@pytest.mark.parametrize("form", COOKIES)
def test_a_cookie_in_any_written_form_is_masked_and_restored(form):
    """Ninth review: ace3572's lookahead and `\\w-` boundary let Go's `Cookie:[...]` and prefixed keys through (a
    regression), and eleven more forms - CGI, PHP, HAR, curl, a jar, an escaped quote - were never reached."""
    text = form % S
    r = redact(text)
    assert S not in r.text, r.text
    assert r.restore(r.text) == text


@pytest.mark.parametrize(
    "text",
    [
        f'{{"authorization": "Bearer 1234567890-{S}"}}',
        f'{{"Authorization":"Bearer {UUID}.{S}"}}',
        f"upstream sent Bearer 123456789012.{S}",
        '{"authorization":"Basic AKIA' + "QWERTYUI" + f'+{S}=="}}',
    ],
)
def test_a_token_whose_start_was_masked_is_masked_whole(text):
    """Ninth review: BEARER and BASIC still stopped at `<`, so the part after a masked start went out in clear."""
    r = redact(text)
    assert S not in r.text, r.text
    assert r.restore(r.text) == text


@pytest.mark.parametrize(
    "first", [f"GET /cart Cookie: _gh_sess={S}; theme=dark", f"password={UUID}.{S}"]
)
def test_a_secret_inside_a_compound_value_is_swept_alone_too(first):
    """Ninth review: masked only as the whole value, the same secret echoed alone on another line stayed in clear."""
    out, _ = redact_many([first, f"session {S} not found in store"])
    assert all(S not in o for o in out), out
