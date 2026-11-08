from core.events.model import MorpheusEvent


def test_event_creation():
    event = MorpheusEvent(
        event_type="authentication_attempt",
        source="test",
        data={
            "username": "admin",
            "success": False,
        },
    )

    result = event.to_dict()

    assert result["event_type"] == "authentication_attempt"
    assert result["source"] == "test"
    assert result["data"]["username"] == "admin"
    assert result["data"]["success"] is False
    assert result["event_id"]
    assert result["timestamp"]


def test_event_store_deduplicates_events(tmp_path):
    from core.storage.event_store import EventStore

    store = EventStore(str(tmp_path / "sensor-events.jsonl"))
    events = [
        {"event_id": "event-1", "data": {"value": 1}},
        {"event_id": "event-2", "data": {"value": 2}},
        {"event_id": "event-1", "data": {"value": 3}},
    ]

    accepted, duplicates = store.save_many_unique(events)

    assert accepted == ["event-1", "event-2"]
    assert duplicates == ["event-1"]
    assert store.count() == 2


def test_event_store_deduplication_survives_new_instance(tmp_path):
    from core.storage.event_store import EventStore

    path = str(tmp_path / "sensor-events.jsonl")

    first = EventStore(path)
    accepted, duplicates = first.save_many_unique([
        {"event_id": "persistent-event", "data": {}}
    ])

    assert accepted == ["persistent-event"]
    assert duplicates == []

    second = EventStore(path)
    accepted, duplicates = second.save_many_unique([
        {"event_id": "persistent-event", "data": {}},
        {"event_id": "new-event", "data": {}},
    ])

    assert accepted == ["new-event"]
    assert duplicates == ["persistent-event"]
    assert second.count() == 2
