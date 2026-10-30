"""S2: write-once audit sink."""

import pytest

from bhovix_core.audit import AuditUnavailable, DuplicateEvent, LocalDirSink
from bhovix_core.models import AuditEvent, sha256_hex


def _event(**kw):
    base = {
        "run_id": "run-1",
        "domain": "gate",
        "operation": "decide",
        "principal": "svc:test-agent",
        "source": "runtime",
    }
    base.update(kw)
    return AuditEvent(**base)


def _break_writes(monkeypatch, sink):
    def boom(event):
        raise OSError("disk gone")

    monkeypatch.setattr(sink, "_write", boom)


def test_duplicate_event_id_refused(tmp_path):
    sink = LocalDirSink(tmp_path)
    ev = _event()
    sink.write_intent(ev)
    with pytest.raises(DuplicateEvent):
        sink.write_intent(ev)
    assert len(sink.events()) == 1


def test_intent_failure_raises(tmp_path, monkeypatch):
    sink = LocalDirSink(tmp_path)
    _break_writes(monkeypatch, sink)
    with pytest.raises(AuditUnavailable):
        sink.write_intent(_event())


def test_outcome_failure_goes_to_outbox_then_reconcile(tmp_path, monkeypatch):
    sink = LocalDirSink(tmp_path)
    original = sink._write
    _break_writes(monkeypatch, sink)
    assert sink.write_outcome(_event(operation="outcome")) is None
    assert len(list(sink.outbox.glob("*.json"))) == 1
    monkeypatch.setattr(sink, "_write", original)
    assert sink.reconcile() == 1
    assert list(sink.outbox.glob("*.json")) == []
    assert [e.operation for e in sink.events("run-1")] == ["outcome"]


def test_events_hold_hashes_only(tmp_path):
    secret_inputs = {"email": "jo@example.test", "bsb": "062-000"}
    sink = LocalDirSink(tmp_path)
    key = sink.write_intent(_event(inputs_hash=sha256_hex(secret_inputs)))
    text = (sink.objects / key).read_text(encoding="utf-8")
    assert "jo@example.test" not in text and "062-000" not in text
    with pytest.raises(ValueError):
        AuditEvent(run_id="r", domain="d", operation="o", principal="p", source="s", inputs=1)


def test_verify_object_catches_a_changed_byte(tmp_path):
    sink = LocalDirSink(tmp_path)
    key = sink.write_intent(_event())
    assert sink.verify_object(key)
    path = sink.objects / key
    data = bytearray(path.read_bytes())
    data[-2] ^= 1
    path.write_bytes(bytes(data))
    assert not sink.verify_object(key)
