import os
import pytest

from telemetry.sensor.queue import SensorDeliveryQueue


def event(event_id, value=None):
    return {
        "event_id": event_id,
        "event_type": "test.event",
        "source": "test",
        "timestamp": "2026-11-08T00:00:00+00:00",
        "data": {"value": value},
    }


def test_persists_across_instances(tmp_path):
    path = str(tmp_path / "queue.jsonl")
    SensorDeliveryQueue(path).enqueue(event("one", 1))
    assert SensorDeliveryQueue(path).pending() == [event("one", 1)]


def test_enqueue_many_deduplicates_pending_ids(tmp_path):
    queue = SensorDeliveryQueue(str(tmp_path / "queue.jsonl"))
    assert queue.enqueue_many([
        event("one", 1), event("one", 2), event("two", 3)
    ]) == 2
    assert [item["event_id"] for item in queue.pending()] == ["one", "two"]


def test_pending_limit_does_not_remove_events(tmp_path):
    queue = SensorDeliveryQueue(str(tmp_path / "queue.jsonl"))
    queue.enqueue_many([event("one"), event("two"), event("three")])
    assert [item["event_id"] for item in queue.pending(2)] == ["one", "two"]
    assert queue.count() == 3


def test_acknowledge_removes_only_specified_ids(tmp_path):
    queue = SensorDeliveryQueue(str(tmp_path / "queue.jsonl"))
    queue.enqueue_many([event("one"), event("two"), event("three")])
    assert queue.acknowledge(["two", "not-present"]) == 1
    assert [item["event_id"] for item in queue.pending()] == ["one", "three"]


def test_acknowledgement_survives_restart(tmp_path):
    path = str(tmp_path / "queue.jsonl")
    queue = SensorDeliveryQueue(path)
    queue.enqueue_many([event("one"), event("two")])
    queue.acknowledge(["one"])
    assert [item["event_id"] for item in SensorDeliveryQueue(path).pending()] == ["two"]


def test_malformed_queue_fails_closed(tmp_path):
    path = tmp_path / "queue.jsonl"
    path.write_text('{"event_id":"ok"}\nnot-json\n', encoding="utf-8")
    queue = SensorDeliveryQueue(str(path))
    with pytest.raises(ValueError, match="Invalid JSON"):
        queue.pending()
    assert path.read_text(encoding="utf-8").endswith("not-json\n")


def test_event_requires_id(tmp_path):
    queue = SensorDeliveryQueue(str(tmp_path / "queue.jsonl"))
    with pytest.raises(ValueError, match="event_id"):
        queue.enqueue({"event_type": "test.event"})


def test_queue_file_permissions_are_0600(tmp_path):
    path = tmp_path / "queue.jsonl"
    SensorDeliveryQueue(str(path)).enqueue(event("private"))
    assert os.stat(path).st_mode & 0o777 == 0o600


def test_pending_rejects_non_positive_limit(tmp_path):
    queue = SensorDeliveryQueue(str(tmp_path / "queue.jsonl"))
    with pytest.raises(ValueError):
        queue.pending(0)
