"""Ported from WARDEN tests/test_redaction_bank.py (PR #206 head 14fc549, veerarakesh56/warden). Kept 16 tests; dropped 5 that need WARDEN-only modules or unported gate policy (listed in the PR).

Bank details (owner order 2026-10-28, lane S2; plan docs/designs/small/redaction-bank-patterns.md, section 4.1).

A BSB, a sort code, an ABA routing number and a Canadian transit or institution number are masked as BANKCODE beside
their keyword; the account number after an account keyword (or straight after its code) as BANKACCT, when a bank word
is near. By shape and context, never by checksum. Each row asserts the exact value-to-kind map, so a deleted pattern
cannot hide behind ACCOUNTID, PHONE or SSN.

Every number here is synthetic (repeated or sequential digits, or a routing number that fails its checksum) and is
built from parts, so no file holds a literal a scanner would flag. The two 12-digit values are the documentation ids
scripts/check_publishable.py allows."""

from __future__ import annotations

import time

import pytest

from hadavin_sdk.guard.redact import redact, redact_many

BC, BA = ("BANKCODE", "BANKACCT")
BSB = "062" + "-000"
ACCT = "1234" + "5678"
ACCT2 = "8765" + "4321"
SORT = "12-34" + "-56"
ABA = "12345" + "6789"
ZERO9 = "0000" + "00000"
DOC12 = "1111" + "22223333"
AWS12 = "1234" + "56789012"
TRANSIT = "123" + "45"
INST = "99" + "9"
CA_ACCT = "765" + "4321"
ACCT7 = "123" + "4567"
UUID_ABA = "3f2a9c1e-0b7d-4b6f-9e21-" + "aba" + "1234" + "56789"
UUID_ACC = "3f2a9c1e-0b7d-4b6f-9e21-" + "acc" + "1234" + "56789"
CARD = "4111 " + "1111 " + "1111 " + "1111"


def _kinds(mapping: dict[str, str]) -> dict[str, str]:
    return {v: k.strip("<>").rsplit("_", 1)[0] for k, v in mapping.items()}


POSITIVE = [
    ("P1", f"BSB {BSB} account {ACCT}", {BSB: BC, ACCT: BA}),
    (
        "P2",
        f"BSB: {'062' + '000'}, Acct No: {'1234 ' + '5678'}",
        {"062" + "000": BC, "1234 " + "5678": BA},
    ),
    (
        "P3",
        f"bsb {'999 ' + '999'} a/c {'000' + '123456'}",
        {"999 " + "999": BC, "000" + "123456": BA},
    ),
    (
        "P4",
        '{"bsb": "' + "123-" + '456", "account_number": "' + "9876" + '5432"}',
        {"123-" + "456": BC, "9876" + "5432": BA},
    ),
    ("P5", f"Sort code: {SORT} Account number: {ACCT2}", {SORT: BC, ACCT2: BA}),
    (
        "P6",
        f"Account No: {'1122' + '3344'}\nSort Code: {'99 88' + ' 77'}",
        {"1122" + "3344": BA, "99 88" + " 77": BC},
    ),
    (
        "P7",
        f"sort_code={'000' + '000'} acct={'0000' + '0000'}",
        {"000" + "000": BC, "0000" + "0000": BA},
    ),
    ("P8", f"ABA {ABA} account {DOC12}", {ABA: BC, DOC12: BA}),
    (
        "P9",
        f"Routing number: {'111-222' + '-333'}\nAccount number: {'4444-5555' + '-66'}",
        {"111-222" + "-333": BC, "4444-5555" + "-66": BA},
    ),
    ("P10", f"RTN#{'98765' + '4321'} acct# {ACCT7}", {"98765" + "4321": BC, ACCT7: BA}),
    ("P11", f"routing_number={ZERO9}, account_number={AWS12}", {ZERO9: BC, AWS12: BA}),
    (
        "P12",
        f"Transit number {TRANSIT} Institution number {INST} Account number {CA_ACCT}",
        {TRANSIT: BC, INST: BC, CA_ACCT: BA},
    ),
    ("P13", f"transit {'99999' + '-001'} account {AWS12}", {"99999" + "-001": BC, AWS12: BA}),
    ("P14a", f"bank account number {'5555' + '6666'} paid", {"5555" + "6666": BA}),
    ("P14b", f"bank a/c {ACCT}", {ACCT: BA}),
    ("P16", f"Pay to sort code {SORT}, account {ACCT2}.", {SORT: BC, ACCT2: BA}),
    (
        "P19",
        f"Transit {TRANSIT} institution {INST} account {CA_ACCT}",
        {TRANSIT: BC, INST: BC, CA_ACCT: BA},
    ),
    ("P20", f"Routing: {ABA}\nAccount: {ACCT}", {ABA: BC, ACCT: BA}),
    (
        "P21",
        f"BSB {BSB} account {'1111' + '1111'}; refund to account {'2222' + '2222'}",
        {BSB: BC, "1111" + "1111": BA, "2222" + "2222": BA},
    ),
    (
        "P22a",
        '{"bank_routing_number":"' + ABA + '","bank_account_number":"' + "5555" + '6666"}',
        {ABA: BC, "5555" + "6666": BA},
    ),
    (
        "P22b",
        f"payee_bsb={'123-' + '456'} beneficiary_account={'3333' + '4444'}",
        {"123-" + "456": BC, "3333" + "4444": BA},
    ),
    (
        "P22c",
        f"dest_sort_code={SORT} bankAccountNumber={'4444' + '5555'}",
        {SORT: BC, "4444" + "5555": BA},
    ),
    ("P23a", f"Acc: {ACCT} BSB {BSB}", {BSB: BC, ACCT: BA}),
    ("P23b", f"Acct. No. {ACCT} sort code {SORT}", {SORT: BC, ACCT: BA}),
    ("P23c", f"BSB:\n{BSB}\nAccount number\n{ACCT}", {BSB: BC, ACCT: BA}),
    ("P23d", f"BSB - {BSB} account {ACCT}", {BSB: BC, ACCT: BA}),
    ("P23e", f"Sort code – {'12–34' + '–56'} account {ACCT}", {"12–34" + "–56": BC, ACCT: BA}),
    (
        "P23f",
        f"Transit/Institution: {TRANSIT + '-003'} account {ACCT7}",
        {TRANSIT + "-003": BC, ACCT7: BA},
    ),
    (
        "P23g",
        f"transit number: {'0' + '12345678'} account {ACCT7}",
        {"0" + "12345678": BC, ACCT7: BA},
    ),
    ("P24a", f"--routing-number {ABA} --account-number {ACCT}", {ABA: BC, ACCT: BA}),
    ("P24b", f"X-BSB: {BSB}\nX-Account-Number: {ACCT}", {BSB: BC, ACCT: BA}),
    ("P24c", f"routing-number: {ABA}", {ABA: BC}),
    ("P24d", f"payee-bank-account: {ACCT} BSB {BSB}", {BSB: BC, ACCT: BA}),
    ("P24e", f"beneficiary-account: {'3333' + '4444'} bsb: {BSB}", {BSB: BC, "3333" + "4444": BA}),
    ("P25a", f"BSB:\xa0{BSB} Account\xa0number: {ACCT}", {BSB: BC, ACCT: BA}),
    ("P25b", f"BSB is {BSB}, account number is {ACCT}", {BSB: BC, ACCT: BA}),
    ("P25c", f"Sort code: {SORT} Account: #{ACCT2}", {SORT: BC, ACCT2: BA}),
    ("P25d", f"BSB {BSB} account {'123 456' + ' 789'}", {BSB: BC, "123 456" + " 789": BA}),
    ("P26a", f"BSB {BSB} {ACCT}", {BSB: BC, ACCT: BA}),
    ("P26b", f"Sort code {SORT}, {ACCT2}", {SORT: BC, ACCT2: BA}),
    ("P26c", f"ABA {ABA} / {DOC12}", {ABA: BC, DOC12: BA}),
    ("P27a", f"Routing/Transit Number: {ABA} Account: {ACCT}", {ABA: BC, ACCT: BA}),
    ("P27b", f"Routing & Transit No. {ZERO9}", {ZERO9: BC}),
    (
        "P27c",
        f"Branch number: {TRANSIT} Institution: {'00' + '3'} Account: {ACCT7}",
        {TRANSIT: BC, "00" + "3": BC, ACCT7: BA},
    ),
    ("P28a", f"*BSB:* {BSB} *Account:* {ACCT}", {BSB: BC, ACCT: BA}),
    ("P28b", f"**Sort code:** {SORT} **Account number:** {ACCT2}", {SORT: BC, ACCT2: BA}),
    (
        "P29a",
        '{"bankRoutingNumber":"' + ABA + '","payeeAccountNumber":"' + ACCT + '"}',
        {ABA: BC, ACCT: BA},
    ),
    ("P29b", f"payeeBsb={BSB} toAccount={ACCT2}", {BSB: BC, ACCT2: BA}),
    ("P30a", f"BSB `{BSB}` account `{ACCT}`", {BSB: BC, ACCT: BA}),
    ("P30b", f"BSB: *{BSB}*", {BSB: BC}),
    ("P30c", f"_BSB:_ {BSB} _Account:_ {ACCT}", {BSB: BC, ACCT: BA}),
    ("P30d", f"BSB `{BSB}` `{ACCT}`", {BSB: BC, ACCT: BA}),
    ("P30e", f"BSB {BSB} - {ACCT}", {BSB: BC, ACCT: BA}),
    ("P31a", f"Acc. No. {ACCT} BSB {BSB}", {ACCT: BA, BSB: BC}),
    ("P31b", f"accounts: {ACCT} sort code {SORT}", {ACCT: BA, SORT: BC}),
    ("P31c", f"Routing Number (ABA): {ABA}", {ABA: BC}),
    ("P31d", f"ABA {ABA} Account Number (Checking): {ACCT}", {ABA: BC, ACCT: BA}),
    (
        "P32a",
        '{\\"bsb\\":\\"' + BSB + '\\",\\"account_number\\":\\"' + ACCT + '\\"}',
        {BSB: BC, ACCT: BA},
    ),
    ("P32b", f"<BSB>{BSB}</BSB><AccountNumber>{ACCT}</AccountNumber>", {BSB: BC, ACCT: BA}),
    ("P32c", '{"bsb"=>"' + BSB + '", "account"=>"' + ACCT + '"}', {BSB: BC, ACCT: BA}),
    ("W1", f"BSB {BSB}" + " " * 88 + f"account {ACCT}", {BSB: BC, ACCT: BA}),
]


@pytest.mark.parametrize(
    ("text", "expected"), [(t, e) for _, t, e in POSITIVE], ids=[i for i, _, _ in POSITIVE]
)
def test_bank_details_are_masked_with_their_exact_kind(text, expected):
    out = redact(text)
    assert _kinds(out.mapping) == expected
    for value in expected:
        assert value not in out.text


@pytest.mark.parametrize(
    ("text", "expected", "kept"),
    [
        (f"BSB {BSB} 2026-10-28 account {ACCT}", {BSB: BC, ACCT: BA}, "2026-10-28"),
        (
            f"sort code {SORT} account {ACCT2} 2026-10-28T10:02:11Z",
            {SORT: BC, ACCT2: BA},
            "2026-10-28T10:02:11Z",
        ),
        (f"BSB {BSB} account {ACCT} 404 not found", {BSB: BC, ACCT: BA}, "404 not found"),
    ],
    ids=["P15a", "P15b", "P18"],
)
def test_a_date_or_status_code_beside_bank_details_is_kept(text, expected, kept):
    out = redact(text)
    assert _kinds(out.mapping) == expected
    for value in expected:
        assert value not in out.text
    assert kept in out.text


def test_P16_punctuation_after_the_account_is_kept():
    assert redact(f"Pay to sort code {SORT}, account {ACCT2}.").text.endswith(">.")


def _many(items: list[str]) -> tuple[list[str], dict[str, str]]:
    lines, mapping = redact_many(items)
    return (lines, _kinds(mapping))


def test_P17_copies_of_an_account_are_swept_from_the_other_lines():
    lines, got = _many([f"BSB {BSB} account {ACCT}", f"refund to {ACCT} failed"])
    assert got == {BSB: BC, ACCT: BA}
    assert lines[1] == "refund to <BANKACCT_1> failed"
    assert not any(v in line for v in got for line in lines)


def test_X1_a_bank_word_anywhere_in_the_batch_is_context():
    lines, got = _many(["payout bsb=" + BSB, "pod restarted", "payout account_number=" + ACCT])
    assert got == {BSB: BC, ACCT: BA}
    assert not any(v in line for v in got for line in lines)


def test_X6_bank_account_in_one_string_is_context_for_the_batch():
    for word in ("bank account", "Bank Accounts", "bank_account", "bank-account"):
        lines, got = _many([f"{word} updated", "pod restarted", "account " + ACCT])
        assert got == {ACCT: BA}, word
        assert ACCT not in lines[2]


def test_X7_redact_takes_related_texts_as_context():
    assert redact("account " + ACCT, near=("payout BSB " + BSB,)).text == "account <BANKACCT_1>"
    assert redact("account " + ACCT, near=("bank account changed",)).text == "account <BANKACCT_1>"
    assert redact("account " + ACCT).text == "account " + ACCT
    assert redact("account " + ACCT, near=("pod restarted",)).text == "account " + ACCT


NEGATIVE = [
    ("N1", f"account {AWS12} assumed role", {"ACCOUNTID"}),
    ("N2", f"Transit Gateway attachment in account {AWS12}", {"ACCOUNTID"}),
    ("N3", "routing table rtb-0abc updated 503 times", None),
    ("N4", "request routing 123456 ms", None),
    ("N5", "Invoice #" + "12345" + "6789 total $1,250.00 due 2026-11-30", None),
    ("N6", "account_id=" + ACCT, {"TENANT"}),
    ("N7", "task 4471 2026-09-11T18:09:10Z", None),
    ("N8", "call +1 415 555 0142", {"PHONE"}),
    ("N9", "amount 1,250.00 for account review", None),
    ("N10a", "institution of record updated", None),
    ("N10b", "in transit: 3 packages", None),
    ("N11", "SEPA transfer to GB29NWBK" + "60161331926819 settled", {"IBAN"}),
    ("N12", f"bank-api pod restarted in account {AWS12}", {"ACCOUNTID"}),
    ("N13a", "BSB", None),
    ("N13b", "sort code", None),
    ("N15", f"a UUID {UUID_ABA}", {"UUID"}),
]


@pytest.mark.parametrize(
    ("text", "kinds"), [(t, k) for _, t, k in NEGATIVE], ids=[i for i, _, _ in NEGATIVE]
)
def test_text_that_is_not_bank_details_is_not_taken_for_them(text, kinds):
    out = redact(text)
    if kinds is None:
        assert out.text == text
    assert set(_kinds(out.mapping).values()) == (kinds or set())


def test_N14_an_account_is_not_swept_out_of_a_longer_number():
    lines, _ = _many([f"BSB {BSB} account {'100' + '200'}", "read 9100200 bytes"])
    assert lines[1] == "read 9100200 bytes"


def test_N16_an_account_keyword_inside_a_uuid_is_part_of_the_uuid():
    out = redact(f"BSB {BSB} request {UUID_ACC}")
    assert _kinds(out.mapping) == {BSB: BC, UUID_ACC: "UUID"}


def test_N17_a_card_number_after_an_account_keyword_stays_a_card():
    out = redact(f"BSB {BSB} card account {CARD}")
    assert _kinds(out.mapping) == {BSB: BC, CARD: "CREDITCARD"}


def test_W2_an_account_past_the_window_is_kept():
    out = redact(f"BSB {BSB}" + " " * 89 + f"account {ACCT}")
    assert _kinds(out.mapping) == {BSB: BC}
    assert ACCT in out.text


@pytest.mark.parametrize(
    ("items", "kinds"),
    [
        ([f"account {AWS12} assumed role", "pod restarted"], {"ACCOUNTID"}),
        ([f"req {UUID_ABA}", f"account {AWS12} assumed role"], {"UUID", "ACCOUNTID"}),
    ],
    ids=["X2", "X3"],
)
def test_a_batch_with_no_bank_word_keeps_its_account_ids(items, kinds):
    _, got = _many(items)
    assert set(got.values()) == kinds


PINNED = [
    ("F1", "in transit: 65536 bytes", {"65536": BC}, []),
    ("F2", "in transit: 65536, 1048576 bytes", {"65536": BC, "1048576": BA}, []),
    ("L2", f"BSB/Account: {BSB} / {ACCT}", {BSB: BA}, [ACCT]),
    ("L3", f"Routing/Account: {ABA} / {ACCT}", {}, [ABA, ACCT]),
    ("L4a", f"| BSB | {BSB} |", None, []),
    ("L4b", f"Sort: {SORT}", None, []),
    ("L4c", f"S/C {SORT}", None, []),
    ("L4d", f"BSB-{BSB}", None, []),
    ("L4e", f"BSB:\n\n{BSB}", None, []),
    ("L4f", f"BSB {BSB} account {'12 345' + '678'}", {BSB: BC}, ["12 345" + "678"]),
    ("L4g", f"sort code and account {SORT} {ACCT2}", {SORT: BA}, [ACCT2]),
    ("L4h", f"Transit {TRANSIT}-003-{ACCT7}", None, []),
    ("L4i", f"ABA (routing) number {ABA}", None, []),
    ("L4j", f"BSB {BSB} /accounts/{ACCT}", {BSB: BC}, [ACCT]),
    ("L4k", f"BSB {BSB} Account ID {ACCT}", {BSB: BC}, [ACCT]),
    ("L4l", f"BSB: _{BSB}_", None, []),
    ("L4m", f"{ACCT} (BSB {BSB})", {BSB: BC}, [ACCT]),
    ("L4n", f"BSB {BSB} toaccount={ACCT}", {BSB: BC}, [ACCT]),
]


@pytest.mark.parametrize(
    ("text", "expected", "kept"),
    [(t, e, k) for _, t, e, k in PINNED],
    ids=[i for i, _, _, _ in PINNED],
)
def test_the_accepted_over_masks_and_limits_are_pinned(text, expected, kept):
    out = redact(text)
    if expected is None:
        assert out.text == text
        return
    got = _kinds(out.mapping)
    if not expected:
        assert not {BC, BA} & set(got.values())
    else:
        assert got == expected
    for value in kept:
        assert value in out.text


def test_L1_a_copy_glued_to_other_characters_is_not_swept():
    lines, _ = _many([f"BSB {BSB} account {ACCT}", f"ref A{ACCT}x"])
    assert f"A{ACCT}x" in lines[1]


def test_T1_a_planted_line_is_read_in_linear_time():
    for text in ("BSB" + " " * 50000 + "x", "account" + " " * 50000 + "x"):
        start = time.process_time()
        redact(text)
        assert time.process_time() - start < 2.0, text[:10]
    start = time.process_time()
    redact_many([f"sort code {SORT} account {ACCT7}{i}" for i in range(2000)])
    assert time.process_time() - start < 15.0
