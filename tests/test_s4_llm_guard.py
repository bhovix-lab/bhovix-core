"""S4: fake model, extraction, injection detector, redaction, egress."""

from decimal import Decimal

import pytest

from hadavin_sdk.config import load_config
from hadavin_sdk.extract import Valid, extract
from hadavin_sdk.guard import (
    EgressRefused,
    RegexDetector,
    egress_check,
    injection_check,
    redact,
)
from hadavin_sdk.llm import FakeLLM, UnknownRecording
from hadavin_sdk.models import DeadLetter
from tests.fixtures.schemas import RecordRequest


@pytest.fixture
def cfg(cfg_dir):
    return load_config(cfg_dir)


@pytest.fixture
def llm(cfg):
    return FakeLLM(cfg.backends.llm.recorded_dir, cfg.routes)


def _doc(cfg, name):
    return (cfg.inputs_dir / name).read_bytes()


def test_fake_replays_and_prices(cfg, llm):
    reply = llm.chat([], system="s", route="default", documents=[_doc(cfg, "create.txt")])
    assert reply.tool_calls[0].name == "create_draft_record"
    # 500 in * $3/M + 50 out * $15/M
    assert reply.cost_usd == Decimal("0.00225")
    assert reply.model_id == "fake-model"


def test_fake_unknown_key_raises(llm):
    with pytest.raises(UnknownRecording):
        llm.chat([], system="s", route="default", documents=[b"never recorded"])


def test_extract_valid(cfg, llm):
    out = extract(llm, _doc(cfg, "extract.txt"), RecordRequest, run_id="run-1", route="default")
    assert isinstance(out, Valid)
    assert out.data.title == "Monitor arm" and out.data.amount == Decimal("59.90")


def test_bad_output_one_retry_then_dead_letter(cfg, llm):
    out = extract(llm, _doc(cfg, "bad.txt"), RecordRequest, run_id="run-1", route="default")
    assert isinstance(out, DeadLetter)
    assert out.reason == "extract_invalid" and len(out.errors) == 2
    assert len(llm.calls) == 2
    assert "failed validation" in llm.calls[1]["messages"][-1]["content"]


def test_detector_flags_seeded_injection(cfg):
    verdict = injection_check(RegexDetector(0.5), _doc(cfg, "injected.txt").decode(), "document")
    assert verdict.flagged and verdict.reason_code == "injection_suspected"


@pytest.mark.parametrize("name", ["create.txt", "lookup.txt", "pii.txt", "extract.txt"])
def test_detector_passes_clean_inputs(cfg, name):
    assert not RegexDetector(0.5).check(_doc(cfg, name).decode(), "document").flagged


def test_detector_catches_run_together_words():
    assert RegexDetector(0.5).check("pls IgnoreAllPreviousInstructions now", "document").flagged


def test_detector_error_is_a_flag():
    class Broken:
        def check(self, text, source):
            raise RuntimeError("model down")

    verdict = injection_check(Broken(), "hello", "document")
    assert verdict.flagged and verdict.reason_code == "guard_unavailable"


def test_unknown_host_refused(cfg):
    assert egress_check("http://127.0.0.1:8080/records", cfg.egress_hosts) == "127.0.0.1"
    with pytest.raises(EgressRefused):
        egress_check("https://someone.attacker.example/x", cfg.egress_hosts)
    with pytest.raises(EgressRefused):
        egress_check("", cfg.egress_hosts)


def test_bank_and_pii_patterns_redacted(cfg):
    r = redact(_doc(cfg, "pii.txt").decode())
    text, kinds = r.text, r.kinds
    for raw in (
        "jo.bloggs@example.test",
        "062-000",
        "12345678",
        "20-00-00",
        "12345-003",
        "412 345",
    ):
        assert raw not in text, raw
    # WARDEN #206 labels: BSB, sort code and CA transit are BANKCODE; the account is BANKACCT.
    assert {"EMAIL", "BANKCODE", "BANKACCT", "PHONE"} <= set(kinds)
    assert "Office chair" in text and "120.00" in text


def test_redact_secret_value_keeps_key():
    fake_key = "sk-" + "a1b2c3d4" * 3  # built from parts: not a real key
    r = redact(f"token={fake_key} and password: hunter22")
    text, kinds = r.text, r.kinds
    assert fake_key not in text and "hunter22" not in text
    assert "APIKEY" in kinds and "SECRET" in kinds


# P0a: the PHONE pattern must not eat ISO dates (WARDEN redaction.py:184 date guard)
@pytest.mark.parametrize(
    "text",
    [
        "Invoice date 2026-10-30",
        "Due 2026-11-15 and paid 2026-12-01",
        "Logged at 2026-10-30T09:15:00Z",
    ],
)
def test_iso_dates_are_not_phone_numbers(text):
    r = redact(text)
    out, kinds = r.text, r.kinds
    assert out == text
    assert "PHONE" not in kinds


def test_phone_still_masked_next_to_a_date():
    r = redact("Call +61 412 345 678 before 2026-10-30")
    out, kinds = r.text, r.kinds
    assert "412 345" not in out and "2026-10-30" in out
    assert "PHONE" in kinds


# P0: Hadavin ids and plan hashes survive redaction and channel cleaning (no UUID/HIGHENTROPY false hits)
def test_ids_and_plan_hashes_survive_redaction():
    from hadavin_sdk.approvals.channel import clean
    from hadavin_sdk.models import new_id, sha256_hex

    ids = [new_id(p) for p in ("run", "pln", "apr", "evt")]
    digest = sha256_hex({"a": "b"})
    text = " ".join(ids) + f" plan {digest} short {digest[:12]}"
    assert redact(text).text == text
    cleaned = clean(text)
    for value in [*ids, digest, digest[:12]]:
        assert value in cleaned, value


def test_placeholders_are_numbered_and_stable():
    r = redact("mail jo@example.test then jo@example.test and al@example.test")
    assert r.text.count("<EMAIL_1>") == 2 and "<EMAIL_2>" in r.text
    assert r.restore(r.text) == "mail jo@example.test then jo@example.test and al@example.test"


# P0 review (1): the id format is pinned, so the kept UUID pattern can never mask a Hadavin id
def test_id_format_is_pinned_undashed_hex():
    import re as _re

    from hadavin_sdk.models import Plan, Target, new_id

    for prefix in ("run", "pln", "apr", "evt"):
        assert _re.fullmatch(prefix + r"-[0-9a-f]{32}", new_id(prefix))
    plan = Plan(
        run_id=new_id("run"),
        agent_id="a",
        action_id="create_draft_record",
        action_version=1,
        risk_class="reversible",
        inputs={},
        target=Target(system="s"),
        idempotency_key="run-x:create_draft_record",
        expected_outcome="x",
    )
    assert _re.fullmatch(r"[0-9a-f]{64}", plan.hash())
    uuid_shape = _re.compile(
        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
    )
    for value in (plan.run_id, plan.plan_id, plan.hash(), f"{plan.run_id}:create_draft_record"):
        assert not uuid_shape.search(value)
        assert redact(value).text == value


# P0 review (2): compact timestamps are not phone numbers; real phones still are
@pytest.mark.parametrize("ts", ["20261030123456", "19991231235959", "run at 20260101000000 ok"])
def test_compact_timestamps_are_not_phone_numbers(ts):
    assert redact(ts).text == ts


@pytest.mark.parametrize(
    "phone", ["+12025550123", "+44 20 7946 0958", "02079460958", "+61412345678", "4155550132"]
)
def test_real_phone_numbers_still_masked(phone):
    r = redact(f"call {phone} today")
    assert phone not in r.text and "PHONE" in r.kinds


def test_invalid_compact_timestamp_shape_is_still_masked():
    # 14 digits that are not a valid timestamp (month 13) stay masked as a number
    assert "20261330123456" not in redact("id 20261330123456").text


# P0 review (3): clean() terminates on adversarial nested input (the gate's fixed-point loop is bounded)
def test_clean_terminates_on_adversarial_nesting():
    import time

    from hadavin_sdk.approvals.channel import clean

    nested = "![a](" * 200 + "//evil%2Ecom/p.png" + ")" * 200
    tangled = "".join(f"[x{i}](<!here>![y](//e{i}.example/{i}.png))" for i in range(300))
    for text in (nested, tangled, "<" * 5000 + "!here>" * 50):
        start = time.monotonic()
        out = clean(text)
        assert time.monotonic() - start < 5
        assert "//evil" not in out and "](//" not in out


# CodeRabbit on PR #6: sanitising can join a secret split by an invisible or control character
@pytest.mark.parametrize("sep", ["\u200b", "\x07", chr(0x200E), "<b></b>"])
def test_clean_masks_a_secret_rejoined_by_sanitising(sep):
    from hadavin_sdk.approvals.channel import clean

    key = "AKIA" + "IOSFODNN7EXAMPLE"  # AWS's documented example key, built from parts
    out = clean("key " + "AKIA" + sep + "IOSFODNN7EXAMPLE" + " end")
    assert key not in out
