"""Text cleaning for anything people read (approval and channel text).

Copied then edited from WARDEN `src/warden/gate.py` @ a1e76cbf (veerarakesh56/warden): rule G3
(`sanitise_text` and its helpers) and G4 (`withhold_commands`, rewritten platform-neutral and fail closed).
Not ported (WARDEN outbound policy): enforce, hedge,
leaked_kinds/data_leaks/assembled_kinds/where_withheld, for_terminal,
outbound_data, sanitise_data, GateResult. The original module notes follow.

The outbound gate: the last check on what WARDEN says before it leaves the process.

v0 (Phase 0 of the v2 re-architecture, 2026-09-27). Two of the planned rules:

- **G3, untrusted text.** Outside code blocks, markdown images, raw HTML, markdown links and bare
  URLs are removed. The model's hypothesis and reasoning are rendered as markdown, and they can
  repeat text an attacker planted in a log line - an image or a link whose URL carries data out.
  The report's own templates contain no URLs, so nothing legitimate is lost. Inside code blocks the
  text is shown verbatim and nothing is followed. Since G1 (audit A-C-9), G3 also:
  - removes protocol-relative `//host` links and link reference definitions;
  - catches `<img/src=...>`;
  - defangs bare domains (`evil[.]com`);
  - strips terminal and text-direction control characters;
  - tracks fences the CommonMark way, so an indented or `~~~` line cannot switch sanitising off;
  - sanitises what follows a fence that is never closed.
  Since the second review (2026-09-30), G3 never writes text it did not inspect:
  - an HTML/character reference is neutralised (`&#96;` -> `&amp;#96;`), never decoded: decoding it
    and writing the result out turned `&#96;&#96;&#96;` into a real fence the gate had never seen;
  - `<` becomes `‹` outside `<KIND_n>` placeholders, so no HTML block, comment or autolink starts;
  - `]:` is broken (no link reference definition, whatever its label spans), and so is a setext
    underline;
  - control characters and CR line endings are removed BEFORE fences are found;
  - a run of three backticks or tildes inside a line is broken - Slack opens code at one anywhere;
  - the inside of a `~~~` block is sanitised like prose: Slack has no `~~~` fences;
  - every domain outside inline code is defanged, whatever its top-level domain, emails included.
  Since the third review (2026-09-30):
  - code regions come from a CommonMark parser (markdown-it-py), not a line tracker: a fence inside
    a list item ends with the item, and Python's `strip()` closed fences CommonMark keeps open. Only
    the body of a CLOSED backtick fence stays verbatim. The gate parses its own output again, and if
    the fences differ from the ones it kept, everything is cleaned as prose;
  - removals run until nothing changes: removing one token could join the rest into a link or image;
  - a line the gate changed starts no block (heading, quote, list, fence, indented code);
  - a mention becomes `at-here` (`(at)here` after a removed link was a link).
- **G5, leaks.** If the final text still contains anything the redactor classes as secret (every
  kind except the identifiers an operator may choose to show), the message is BLOCKED and a stub
  goes out instead: a person reads the full report locally.

- **G2, unverifiable claims** (`hedge`, Phase 1). The model may write "no customer impact", "no data
  was lost" or "the issue is resolved". WARDEN verifies none of these: it reads no impact data, and
  it checks no outcome (that is Phase 2's success check). Each such claim in model-written text is
  marked `[unverified: ...]` where it stands. "The root cause is" is not marked: the report already
  heads the model's text as its hypothesis, with its confidence.

- **G4, commands** (`withhold_commands`, 2026-10-16). WARDEN prints no command for a person to run:
  its reports carry none, and a write command (aws, kubectl, helm, terraform, SQL, `rm -r`,
  `curl | sh`) in model-written prose is withheld where it stands, as the model's answer is read
  (models.ModelProse, discuss.Answer). A change goes only through a catalogue plan and a signed
  approval.

Every way out uses this module (audit A-C-8):
- chat sinks: `enforce`, with G5 also over the text as built, before notify re-redacts it;
- stdout: `for_terminal`;
- MCP results and generic webhooks: `outbound_data`.

Verdicts: PASS (unchanged), REWRITE (G3 removed something), BLOCK (G5). G1 (every claim grounded) is
P13 in the verifier; the report says when it fired.
"""

from __future__ import annotations

import html
import re

from markdown_it import MarkdownIt

from hadavin_sdk.guard.redact import strip_ansi

# A link label may hold escaped brackets (`[a\]b]`); a destination may be anything but `)`.
_LABEL = r"\[((?:[^\]\\\n]|\\.)*)\]"
_IMAGE = re.compile(r"!" + _LABEL + r"\([^)]*\)")
# Any inline link, whatever its target: `//host/...` (protocol-relative) carries data out as well as
# `https://` does (audit A-C-9).
_MDLINK = re.compile(_LABEL + r"\(\s*[^)\s]+[^)]*\)")
# A link reference definition `[x]: target`, also inside a list item or a quote, and with an escaped
# label - CommonMark accepts all three (independent review 2026-09-28: `- [r]: h&#116;tps://...`
# plus `![x][r]` rendered a zero-click image with verdict PASS).
_REFDEF = re.compile(r"^\s{0,3}(?:(?:[-*+]|\d{1,9}[.)])\s+|>\s*)*" + _LABEL + r":\s*\S")
# Any scheme with `//`, the schemes that act without one, and protocol-relative `//host.`.
# Any scheme, one letter too (`p://evil.com` - ninth review), and a bare `://host`.
_URL = re.compile(
    r"(?:\b[a-z][a-z0-9+.\-]{0,30}://|(?<![\w:])://[\w-]+(?:\.|%2e)|\b(?:https?|mailto|data|javascript|vbscript|tel|slack|"
    r"ms-teams|vscode|ssh|smb|file|sms|facetime|skype|zoommtg|itms-services):"
    r"|(?<![\w:/])//[\w-]+(?:\.|%2e))[^\s)>\]'\"`]*",
    re.IGNORECASE,
)
# An IP address with a port or a path is a link to a chat client.
_IP_LINK = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5})?/\S*")
# A tag, not a `<TENANT_1>` placeholder (placeholders carry `_`, which a tag name never does here).
# `<img/src=...>` is a tag too: a `/` may separate the name from its attributes (audit A-C-9). Tags are
# also removed ACROSS lines before the line pass: `<img\nsrc=...>` is one tag to a renderer.
_HTML = re.compile(r"</?[a-zA-Z][a-zA-Z0-9-]*(?:[\s/][^<>]*)?>", re.DOTALL)
# Slack's own control syntax: <!channel>, <!here>, <!subteam^S1>, <@U123>, <#C123>, <url|text>. And
# the bare words a client may still expand.
_SLACK = re.compile(r"<[!@#][^<>]*>|<[a-z][a-z0-9+.\-]*:[^<>|]*\|[^<>]*>", re.IGNORECASE)
_MENTION = re.compile(r"(?<![\w@])@(here|channel|everyone)\b", re.IGNORECASE)
# Bare domains are defanged (`evil[.]com`) so a chat client does not turn them into links - data can
# ride in a subdomain or a path (audit A-C-9). Every two-letter top-level domain (country codes), the
# common generic ones, punycode, and any non-ASCII label (lookalikes such as a Cyrillic "е") are
# covered - a partial list let `evil.sh`, `evil.it` and `evil.zip` through (review 2026-09-28).
# Any alphabetic top-level domain: a list let `evil.digital` through (second review, 2026-09-30),
# and Slack links a bare domain under any real TLD.
_TLDS = r"[a-z]{2,24}|xn--[a-z0-9-]+|[^\x00-\x7f\W\d_]{2,}"
# Not an email's local part (`priya.nair@`): only what follows the `@` is a host.
_DOMAIN = re.compile(rf"(?<![\w.\[/-])((?:[\w-]+\.)+)({_TLDS})(?![\w@-])", re.IGNORECASE)
# Labels holding a non-ASCII character. Bounded as DNS bounds a name (labels of 63, at most 127 of them; Sonar
# python:S8786, 2026-10-16): unbounded, a long run of such letters was split every way it could be. A longer one is
# no host, and what passes the bounds is defanged in pieces.
_NON_ASCII_HOST = re.compile(
    r"(?<![\w@.\[/-])((?:[\w-]{0,62}[^\x00-\x7f][\w-]{0,62}\.){1,127})([\w-]{1,63})"
)
# CommonMark fences: at most 3 spaces of indent, ``` or ~~~, closed by the same character at least as
# long. `lstrip().startswith("```")` let a 4-space-indented or ~~~ line flip the state and leave the
# rest of the message unsanitised (audit A-C-9).
_FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})")
# Terminal and text-direction control characters: an ESC sequence can rewrite what a terminal shows
# (or make a hyperlink); bidi overrides reorder what a reader sees.
_CONTROL = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f\u200e\u200f\u202a-\u202e\u2066-\u2069]")
# A reference CommonMark would decode. `&amp;` itself is left: it decodes to a plain `&`.
# ASCII: `\d` is 0-9 only, as CommonMark reads a decimal reference.
_ENTITY = re.compile(
    r"&(?!amp;)(#\d{1,7};|#[xX][0-9a-fA-F]{1,6};|[A-Za-z][A-Za-z0-9]{1,31};)", re.ASCII
)
_LT = re.compile(r"<(?![A-Z][A-Z0-9]*_\d+>)")
_RUN = re.compile(r"`{3,}|~{3,}")
_BLOCK_START = re.compile(r"^ {0,3}(?:#{1,6}(?:[ \t]|$)|>|[`~]{3})")
# Any block a line can start: heading, quote, list item, fence, indented code (third review: removing
# `<b>` from `<b>## Fix - approved` left a real heading).
_ANY_BLOCK = re.compile(
    r"^(?: {0,3}(?:#{1,6}(?:[ \t]|$)|>|[-*+](?:[ \t]|$)|\d{1,9}[.)](?:[ \t]|$)|[`~]{3})"
    r"| {4}|[ ]{0,3}\t)"
)
_MD = MarkdownIt("commonmark")
# The opener or closer of a fence, after any container markers (list items, quotes). A backtick
# fence's info string holds no backtick.
_FENCE_LINE = re.compile(
    r"^([ \t>*+\-0-9.)]*?)(`{3,}+(?=[^`]*$)|~{3,}+)(.*)$"
)  # possessive: a fence is all its marks (Sonar python:S8786, 2026-10-16)
_SETEXT = re.compile(r"^ {0,3}(?:=+|-+)[ \t]*$")
# Inline code both CommonMark and Slack agree on: single backticks, not escaped, nothing inside.
_INLINE_CODE = re.compile(r"(?<![`\\])(`[^`\n]+`)(?!`)")


def strip_controls(text: str) -> str:
    return _CONTROL.sub("", text)


def _defang(m: re.Match[str]) -> str:
    # Every dot: GFM links `www.evil` on its own, so `www.evil[.]digital` was still a link.
    return m.group(0).replace(".", "[.]")


def _break_runs(line: str) -> str:
    return _RUN.sub(lambda m: "\u200b".join(m.group(0)), line)


# Dots a browser turns into "." when a link is opened (fifth review, 2026-10-01: `evil` + U+3002 + `com`
# passed): written as ASCII dots, so the domain is defanged like any other.
_WIDE_DOTS = re.compile("[\u3002\uff0e\uff61]")
# An invisible character next to a dot keeps a domain whole to the matcher, not to a reader or a browser (sixth
# review, 2026-10-01: `evil.<ZWSP>com`, `evil.c<SHY>om`). Removed inside a name before a domain is matched.
# The code points a WHATWG URL parser drops from a host (Node 22's, over all 1.1M code points; seventh review,
# 2026-10-01): a browser joins `evil.<U+FE0F>com` into one domain. Not ZWNJ/ZWJ: the parser keeps those, and
# removing them rewrote Persian text.
# The two astral ranges (shorthand format controls, variation selectors 17-256) are added with chr(): SonarCloud
# reads an 8-digit \U escape in a character class as separate characters and reports duplicates Python does not have.
_INVISIBLE = re.compile(
    r"[\u00ad\u034f\u180b-\u180d\u180f\u200b\u2060\u2064\ufe00-\ufe0f\ufeff"
    f"{chr(0x1BCA0)}-{chr(0x1BCA3)}{chr(0xE0100)}-{chr(0xE01EF)}]+"
)


# Only between ASCII name characters - where it hides a link or splits a key - not everywhere: removing U+FE0F
# everywhere broke emoji, a CJK or Mongolian variation selector was lost (ninth review, 2026-10-01).
_INVISIBLE_IN_NAME = re.compile(
    r"(?<=[A-Za-z0-9_.:/@\-])" + _INVISIBLE.pattern + r"(?=[A-Za-z0-9_.:/@\-])"
)
# A terminal escape written out as text - argparse's repr() of an argument: `'\x1b[2JAKIA...'`.
_ANSI_AS_TEXT = re.compile(r"(?:\\x1[bB]|\\033|\\[eE]|\\u001[bB])\[[0-?]*[ -/]*[@-~]")


def normalise(text: str) -> str:
    """The text as a browser or a terminal reads it: no control characters, none of the code points a URL parser
    drops. Done FIRST - before the leak check and before links are removed: done after, `htt<SHY>p://evil.com` hid
    from link removal and the gate itself then joined it into a live link, and `AKIA<ZWSP>...` passed G5 and
    went out whole (eighth review, 2026-10-01)."""
    return _INVISIBLE_IN_NAME.sub("", strip_controls(strip_ansi(text)))


# Emphasis, strike and code markers. Not `_`: a key split by it is whole as written already (`\w` holds it).
_RENDERED_MARKUP = re.compile(r"[*~`]")


def _views(text: str) -> set[str]:
    """Every way a reader may see `text`: as written; without escape sequences (a space where one glued two words,
    and also written out as text); without control characters; and without any invisible character. A key split
    by one of them is whole in some view, and a key the removal glues to a letter is bounded in another (ninth
    review: checking only the normalised text sent `x<BEL>AKIA...` whole)."""
    views = {text, strip_ansi(text), _ANSI_AS_TEXT.sub(" ", text)}
    views |= {strip_controls(v) for v in views}
    views |= {_INVISIBLE.sub("", v) for v in views}
    return views


def _rendered(views: set[str]) -> set[str]:
    """As a renderer shows them (register R9-O1): Slack and Markdown consume emphasis, strike and code markers and
    decode entities, so `AKIA**IOSFODNN7...**` and `AKIA&amp;...` show a key joined that no view held whole."""
    return {_RENDERED_MARKUP.sub("", html.unescape(v)) for v in views}


def _defang_outside_code(line: str) -> str:
    """Domains are defanged except inside inline code, where no renderer makes a link. Only when the
    line's backticks are unambiguous (no double run) - otherwise everything is defanged."""
    parts = [line] if "``" in line else _INLINE_CODE.split(line)
    return "".join(
        part
        if i % 2
        else _DOMAIN.sub(_defang, _NON_ASCII_HOST.sub(_defang, _WIDE_DOTS.sub(".", part)))
        for i, part in enumerate(parts)
    )


def _clean_line(line: str) -> str:
    # ⛔ Nothing here decodes: the gate writes out exactly the text it checked (second review,
    # 2026-09-30). A reference is neutralised below instead, so `h&#116;tps://` is never a link and
    # `&#96;&#96;&#96;` never a fence, in any renderer.
    line = normalise(line)
    # To a fixed point: removing one token can join what is left into a new one (third review:
    # `![a]<!here>(//evil%2Ecom/p.png)` became an image once `<!here>` was gone).
    for _ in range(50):
        if _REFDEF.match(line):
            return "[link definition removed]"
        before = line
        line = _IMAGE.sub("[image removed]", line)
        line = _MDLINK.sub(r"\1 [link removed]", line)
        line = _SLACK.sub("", line)
        line = _URL.sub("[link removed]", line)
        line = _IP_LINK.sub("[link removed]", line)
        line = _HTML.sub("", line)
        if line == before:
            break
    line = _LT.sub("\u2039", line)
    line = _ENTITY.sub(r"&amp;\1", line)
    line = _break_runs(line.replace("]:", "]\u200b:"))
    line = _MENTION.sub(r"at-\1", line)  # not `(at)`: after `[link removed]` that is a link
    return _defang_outside_code(line)


def _clean_prose(lines: list[str]) -> list[str]:
    """One run of non-code lines: tags that span lines go first, then each line."""
    if not lines:
        return []
    joined = _HTML.sub("", "\n".join(lines)).split("\n")
    out = [_clean_line(line) for line in joined]
    # A line cleaning changed starts no block: the gate did not write that structure, the input did not
    # have it. (A tag across lines shifts the lines: then every line counts as changed.)
    same = len(joined) == len(lines)
    out = [
        "\u200b" + c if _ANY_BLOCK.match(c) and not (same and c == lines[i]) else c
        for i, c in enumerate(out)
    ]
    # A setext underline turns the line above it into a heading.
    return [
        "\u200b" + line if i and _SETEXT.match(line) and out[i - 1].strip() else line
        for i, line in enumerate(out)
    ]


def _closed_fences(text: str) -> list[tuple[int, int, str]]:
    """(opener line, closer line, marker character) of every CLOSED fence, as CommonMark reads the
    text - inside lists and quotes too, where a fence ends with its container (third review,
    2026-09-30). An unclosed fence is not listed: Slack shows its marker as text, so it is prose."""
    lines = text.split("\n")
    spans = []
    for t in _MD.parse(text):
        if t.type != "fence" or not t.map:
            continue
        start, last = t.map[0], t.map[1] - 1
        m = _FENCE_LINE.match(lines[last]) if last > start else None
        if (
            m
            and m.group(2)[0] == t.markup[0]
            and len(m.group(2)) >= len(t.markup)
            and not m.group(3).strip(" \t")
        ):
            spans.append((start, last, t.markup[0]))
    return spans


def _all_prose(lines: list[str]) -> str:
    return "\n".join(_clean_prose(lines))


def sanitise_text(text: str) -> str:
    """G3 over markdown. Only the body of a CLOSED backtick fence stays verbatim - CommonMark shows it
    as code and Slack toggles code on its ``` lines. A closed `~~~` fence stays a fence with its body
    cleaned (Slack has no `~~~`); everything else, indented code included, is cleaned as prose. The code regions come from a CommonMark parser, and the output is
    parsed again: if its fences are not exactly the ones kept, everything is cleaned as prose."""
    # CR is a line ending to CommonMark. The parser reads the text as a renderer gets it, controls
    # included: a control before ``` makes that line prose, which is cleaned - and cleaning strips the
    # control, breaks the run, and counts the line as changed, so it starts no block.
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    out: list[str] = []
    kept: list[tuple[int, int]] = []
    pos = 0
    for start, last, char in _closed_fences("\n".join(lines)):
        opener, closer = _FENCE_LINE.match(lines[start]), _FENCE_LINE.match(lines[last])
        if not opener or not closer:
            return _all_prose(lines)
        out += _clean_prose(lines[pos:start])
        begin = len(out)
        # Markers normalised to three: the body holds no run, so three close it as the original marker
        # did. The info string is cleaned (Slack shows it).
        out.append(opener.group(1) + char * 3 + _clean_line(opener.group(3)))
        body = lines[start + 1 : last]
        # A backtick body is code in both readers (Slack closes code at ``` anywhere, so runs are broken;
        # a control could hide one). Slack has no ~~~: that body is prose to it and is cleaned.
        out += (
            [_break_runs(strip_controls(line)) for line in body]
            if char == "`"
            else [_clean_line(line) for line in body]
        )
        out.append(closer.group(1) + char * 3)
        kept.append((begin, len(out) - 1, char))
        pos = last + 1
    out += _clean_prose(lines[pos:])
    result = "\n".join(out)
    markers = {i for k in kept for i in k[:2]}
    if _closed_fences(result) != kept or _RUN.search(
        "\n".join(line for i, line in enumerate(out) if i not in markers)
    ):
        return _all_prose(lines)
    return result


_UNVERIFIABLE = re.compile(
    r"\b(?:no|zero|without any|not any)\s+(?:customer|user|client|business)s?\s+(?:impact|were affected|was affected|affected)"
    r"|\bno\s+(?:customers?|users?|clients?)\s+(?:were|was|are|is)\s+affected"
    r"|\bno\s+data\s+(?:was\s+|were\s+)?(?:lost|loss|affected|corrupted|leaked)"
    r"|\b(?:has|have)\s+(?:been\s+)?(?:resolved|fixed|mitigated|recovered)"
    r"|\b(?:is|are|was|were)\s+(?:now\s+)?(?:resolved|fixed|mitigated|recovered)"
    # Register N1: the model reads evidence and runs nothing, so a check it says it ran is false by construction.
    r"|\b(?:I|we)\s+(?:have\s+|also\s+)?(?:checked|verified|confirmed|inspected|tested|ran|queried|validated)\b"
    r"|\b(?:after|upon)\s+(?:checking|verifying|inspecting|testing|querying)\b",
    re.IGNORECASE,
)


# G4: no command a person could paste to change a system reaches them. A change goes only through an action
# contract, the gate and a signed approval, which the executor runs itself. Model-derived text can still carry one
# (a hijacked model, or a log line it repeats), so each command in it is withheld where it stands.
#
# Ported from WARDEN `withhold_commands` (gate.py @ a1e76cbf), which named write shapes for the AWS CLI, kubectl,
# helm, terraform and SQL only, so any other platform's command passed (lock-in audit 2026-10-31, row 13).
# Platform-neutral and FAIL CLOSED here: for every CLI below, a command is withheld unless it is positively
# recognised as read-only (a read verb in its subcommand chain and no write verb). The SQL, `rm -rf`, `curl | sh`
# and PowerShell shapes have no read list, so they stay write shapes.
#
# A command, not the story of one (WARDEN measured 2,035 recorded model strings, 2026-10-16): the model says what
# happened ("a 'kubectl rollout restart' replaced the pods"). So a program name counts only in lower case, followed
# by a subcommand chain that ENDS like a command: the line or text ends, a flag or a shell operator follows, or an
# argument with a path, digit, `:`, `=` or `@` does. A chain that runs on into prose (a quote, a comma, a fifth
# plain word) is a story. `git`, `docker`, `podman` and `helm` are also English words or nouns in incident prose,
# so they count only where a command is written: at the start of a line, after `$`, `sudo`, a shell operator or a
# backtick, or with a flag. Each program with a fixed command set must name one of its own subcommands first.
# Linear: each name is matched once, then at most _MAX_TOKENS tokens are read after it, never re-scanned.
WITHHELD = "[command withheld (G4)]"
_MAX_TOKENS = 12
_MAX_WORDS = 4


def _words(s: str) -> frozenset[str]:
    return frozenset(s.split())


# Write verbs in any CLI. A chain holding one is never read-only, whatever read verb it also holds.
_WRITE_VERBS = _words(
    "add annotate apply attach autoscale cordon cp create del delete deploy destroy detach disable down drain drop "
    "edit enable exec expose grant import install invoke kill label modify move mv patch prune purge push put "
    "reboot remove replace reset restart revoke rm rmi rollback run scale set start stop sync taint terminate "
    "uncordon uninstall unset up update upgrade"
)
_AWS_READ_PREFIXES = ("describe-", "get-", "list-", "head-", "batch-get-", "lookup-", "search-")

# program -> (its own first-level subcommands, or None when the set is open; read verbs)
_PROGRAMS: dict[str, tuple[frozenset[str] | None, frozenset[str]]] = {
    "aws": (None, _words("ls scan query wait")),
    "gcloud": (None, _words("describe list get-iam-policy get-value read info version")),
    "gsutil": (None, _words("ls cat du stat hash version")),
    "bq": (None, _words("ls show head version")),
    "az": (None, _words("show list version")),
    "azcopy": (None, _words("list jobs show env version")),
    "kubectl": (
        _words(
            "annotate api-resources api-versions apply attach auth autoscale certificate cluster-info completion "
            "config cordon cp create debug delete describe diff drain edit events exec explain expose get kustomize "
            "label logs patch plugin port-forward proxy replace rollout run scale set taint top uncordon version "
            "wait"
        ),
        _words(
            "get describe logs top explain version api-resources api-versions cluster-info diff events "
            "status history can-i"
        ),
    ),
    "helm": (
        _words(
            "create dependency diff env get history install lint list ls package plugin pull push registry "
            "repo rollback search show status template test uninstall upgrade verify version"
        ),
        _words("get history lint list ls search show status template verify version env diff"),
    ),
    "terraform": (
        _words(
            "init validate plan apply destroy console fmt force-unlock get graph import login logout "
            "metadata output providers refresh show state taint test untaint version workspace"
        ),
        _words("plan validate show output providers graph version list"),
    ),
    "pulumi": (
        _words(
            "about cancel config convert destroy import install login logout logs new org package plugin "
            "policy preview refresh schema stack state up update version watch whoami"
        ),
        _words("about preview logs whoami version ls output get"),
    ),
    "ansible": (None, _words("version")),
    "ansible-playbook": (None, _words("syntax-check list-tasks list-hosts")),
    "systemctl": (
        None,
        _words(
            "status show cat list-units list-unit-files list-timers list-sockets is-active is-enabled "
            "is-failed is-system-running get-default"
        ),
    ),
    "psql": (None, frozenset()),
    "mysql": (None, frozenset()),
    "mongosh": (None, frozenset()),
    "redis-cli": (None, _words("ping info get keys scan ttl type exists")),
    "git": (
        _words(
            "add am apply bisect blame branch checkout cherry-pick clean clone commit describe diff fetch "
            "grep init log merge mv pull push rebase reflog remote reset restore revert rm show stash status "
            "switch tag worktree rev-parse ls-files"
        ),
        _words("blame describe diff grep log reflog show status rev-parse ls-files"),
    ),
    "gh": (None, _words("view list status diff checks")),
    "glab": (None, _words("view list status diff")),
}
_PROGRAMS["tofu"] = _PROGRAMS["terraform"]
_PROGRAMS["oc"] = (
    _PROGRAMS["kubectl"][0]
    | _words("adm new-app new-project project projects start-build status whoami"),
    _PROGRAMS["kubectl"][1] | _words("status whoami projects"),
)
for _name in ("docker", "podman"):
    _PROGRAMS[_name] = (
        _words(
            "attach build commit compose container cp create diff events exec export history image images "
            "import info inspect kill load login logout logs network pause plugin port ps pull push rename "
            "restart rm rmi run save search start stats stop system tag top unpause update version volume wait"
        ),
        _words("diff events history images info inspect logs ps port search stats top version ls"),
    )

_CODE_ONLY = frozenset({"git", "docker", "podman", "helm", "ansible"})

_PROGRAM = re.compile(
    r"(?<![\w./-])("
    + "|".join(re.escape(p) for p in sorted(_PROGRAMS, key=len, reverse=True))
    + r")(?![\w-])"
)
_TOKEN = re.compile(r"[ \t]+(-{1,2}[A-Za-z0-9][\w-]*(?:=\S*)?|\S+)")
_WORD = re.compile(r"[a-z][a-z0-9-]*")
_ARG_CHARS = re.compile(
    r"[/\d:=@.\\\['\"`]"
)  # `[` too: G3 leaves `[link removed]` where a URL stood
_QUOTED_WORD = re.compile(r"[a-z][a-z0-9-]*[\"'`)\]]+")
_WORD_THEN_STOP = re.compile(r"[a-z][a-z0-9-]*[.,;:!?]")
_SHELL_OP = re.compile(r"[ \t]*(?:[;|&]|$)", re.MULTILINE)
_CODE_BEFORE = re.compile(r"(?:^|[`$;|&(]|\bsudo)[ \t]*$", re.MULTILINE)

# Write shapes with no read form to recognise (WARDEN's, plus the INSERT/GRANT/CREATE and PowerShell additions).
_WRITE_SHAPES = re.compile(
    r"\bpg_(?:cancel|terminate)_backend\s*\("
    r"|\bALTER\s+(?:DATABASE|INDEX|ROLE|SCHEMA|TABLE|USER)\s+\S+\s+(?:ADD|ALTER|ATTACH|DETACH|DISABLE|DROP|ENABLE|"
    r"OWNER|RENAME|RESET|SET|VALIDATE)\b|\bALTER\s+SYSTEM\s+(?:SET|RESET)\b"
    r"|\b(?:DROP|TRUNCATE)\s+(?:DATABASE|INDEX|ROLE|SCHEMA|TABLE|USER)\s+(?:IF\s+EXISTS\s+)?[\w.\"]+"
    r"|\bCREATE\s+(?:DATABASE|INDEX|ROLE|SCHEMA|TABLE|USER)\s+[\w.\"]+"
    r"|\bDELETE\s+FROM\s+[\w.\"]+|\bUPDATE\s+[\w.\"]+\s+SET\b|\bINSERT\s+INTO\s+[\w.\"]+"
    r"|\b(?:GRANT|REVOKE)\s+[A-Z, ]+\s+ON\b"
    r"|\b(?!Get-)[A-Z][a-z]+-Az[A-Z][A-Za-z]*\b"
    r"|\b(?:Remove-Item|Stop-Service|Stop-Process|Restart-Service|Restart-Computer|Stop-Computer)\b"
    r"|\brm\s+-[a-zA-Z]*[rRf][a-zA-Z]*(?=\s+\S)"
    r"|\b(?:curl|wget)\s[^|\n]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b"
)


def _command_end(text: str, prog: str, start: int) -> tuple[int, bool] | None:
    """Where the command that starts at `start` ends, and whether it is read-only; None for a story."""
    pos, chain, flag, arg, ended = start, [], False, False, False
    for _ in range(_MAX_TOKENS):
        m = _TOKEN.match(text, pos)
        if (
            m is None
        ):  # the line or text ends here, or a quote or bracket follows the word: decided below
            break
        tok = m.group(1)
        stop = _WORD_THEN_STOP.fullmatch(tok)  # `nginx.` / `web,`: the command ends with the clause
        if tok.startswith("-"):
            flag = True
        elif stop or _WORD.fullmatch(tok):
            chain.append(tok.rstrip(".,;:!?"))
            if len(chain) > _MAX_WORDS:
                return None  # it runs on into prose: a story
        elif _ARG_CHARS.search(tok) and not _QUOTED_WORD.fullmatch(tok):
            arg = ended = True  # an argument: a path, a name with digits, key=value, a quoted value
        else:  # `Lambda`, `restart'`: prose, unless flags already made it a command
            break
        pos = m.end()
        if stop or ended:
            ended = True
            break
    else:
        ended = True
    ended = ended or flag or bool(_SHELL_OP.match(text, pos))
    own, read = _PROGRAMS[prog]
    if (
        not ended
        or not (chain or flag or arg)
        or (own is not None and not any(t in own for t in chain))
    ):
        return None
    if prog in _CODE_ONLY and not flag and not _CODE_BEFORE.search(text, 0, start - len(prog)):
        return None
    writes = any(t in _WRITE_VERBS for t in chain)
    if prog == "aws":
        readonly = not writes and any(t.startswith(_AWS_READ_PREFIXES) or t in read for t in chain)
    else:
        readonly = not writes and any(t in read for t in chain)
    return pos, readonly


def withhold_commands(text: str) -> str:
    """G4 over one piece of model-derived text: each command not positively recognised as read-only is replaced
    where it stands (the program and its subcommand chain), so what is left cannot be pasted and run."""
    text = _WRITE_SHAPES.sub(WITHHELD, text)
    out, last = [], 0
    for m in _PROGRAM.finditer(text):
        if m.start() < last:
            continue
        found = _command_end(text, m.group(1), m.end())
        if found is None or found[1]:
            continue
        out += [text[last : m.start()], WITHHELD]
        last = found[0]
    return "".join(out) + text[last:]
