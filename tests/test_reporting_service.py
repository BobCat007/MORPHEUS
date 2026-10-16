import json

import pytest

from core.storage.event_store import EventStore
from reporting.service import generate_incident_report_from_store


def make_analysis_event(session_id, source_ip, command):
    """Build a stored intelligence event for testing."""

    return {
        "event_id": "event-{}".format(session_id),
        "event_type": "morpheus.intelligence.analysis",
        "source": "morpheus",
        "timestamp": "2026-10-16T10:00:00+00:00",
        "data": {
            "session": {
                "session_id": session_id,
                "source_ip": source_ip,
                "protocol": "ssh",
                "commands": [command],
                "command_events": [
                    {
                        "command": command,
                        "timestamp": "2026-10-16T10:00:01+00:00",
                    }
                ],
                "start_time": "2026-10-16T10:00:00+00:00",
                "end_time": "2026-10-16T10:00:02+00:00",
                "duration_ms": 2000,
            },
            "fingerprint": {
                "fingerprint_id": "fingerprint-{}".format(session_id),
                "session_count": 1,
                "command_count": 1,
            },
            "intents": [],
            "mitre_techniques": [],
            "campaign": None,
            "risk_assessment": {
                "session_id": session_id,
                "score": 10,
                "severity": "low",
                "factors": [],
            },
            "recommended_actions": [],
            "deception": {
                "enabled": False,
                "applied": False,
            },
        },
    }


def test_event_store_reads_events_in_insertion_order(tmp_path):
    store = EventStore(str(tmp_path / "events.jsonl"))

    first = {"event_type": "test.first", "data": {"number": 1}}
    second = {"event_type": "test.second", "data": {"number": 2}}

    store.save(first)
    store.save(second)

    assert store.read_all() == [first, second]
    assert store.count() == 2


def test_event_store_returns_empty_list_when_file_does_not_exist(
    tmp_path,
):
    store = EventStore(str(tmp_path / "missing" / "events.jsonl"))

    assert store.read_all() == []
    assert store.count() == 0


def test_event_store_rejects_malformed_jsonl(tmp_path):
    storage_path = tmp_path / "events.jsonl"
    storage_path.write_text(
        '{"event_type": "valid"}\n'
        '{"event_type": invalid}\n',
        encoding="utf-8",
    )

    store = EventStore(str(storage_path))

    with pytest.raises(ValueError, match="line 2"):
        store.read_all()


def test_service_generates_report_for_requested_session(tmp_path):
    storage_path = tmp_path / "events.jsonl"
    output_path = tmp_path / "reports" / "incident.json"

    store = EventStore(str(storage_path))
    store.save(
        make_analysis_event(
            "session-a",
            "192.0.2.10",
            "whoami",
        )
    )
    store.save(
        make_analysis_event(
            "session-b",
            "192.0.2.20",
            "ls",
        )
    )

    report = generate_incident_report_from_store(
        storage_path=str(storage_path),
        session_id="session-b",
        output_path=str(output_path),
        generated_at="2026-10-16T12:00:00+00:00",
    )

    assert report["session"]["session_id"] == "session-b"
    assert report["session"]["source_ip"] == "192.0.2.20"
    assert report["session"]["commands"] == ["ls"]
    assert output_path.is_file()

    saved_report = json.loads(
        output_path.read_text(encoding="utf-8")
    )
    assert saved_report == report


def test_service_uses_latest_matching_analysis(tmp_path):
    storage_path = tmp_path / "events.jsonl"
    output_path = tmp_path / "incident.json"

    store = EventStore(str(storage_path))
    store.save(
        make_analysis_event(
            "session-a",
            "192.0.2.10",
            "whoami",
        )
    )
    store.save(
        make_analysis_event(
            "session-a",
            "192.0.2.11",
            "id",
        )
    )

    report = generate_incident_report_from_store(
        storage_path=str(storage_path),
        session_id="session-a",
        output_path=str(output_path),
        generated_at="2026-10-16T12:00:00+00:00",
    )

    assert report["session"]["source_ip"] == "192.0.2.11"
    assert report["session"]["commands"] == ["id"]


def test_service_rejects_empty_session_id(tmp_path):
    with pytest.raises(ValueError, match="session_id"):
        generate_incident_report_from_store(
            storage_path=str(tmp_path / "events.jsonl"),
            session_id=" ",
            output_path=str(tmp_path / "incident.json"),
        )


def test_service_raises_when_store_has_no_matching_session(tmp_path):
    storage_path = tmp_path / "events.jsonl"
    output_path = tmp_path / "incident.json"

    EventStore(str(storage_path)).save(
        make_analysis_event(
            "another-session",
            "192.0.2.30",
            "whoami",
        )
    )

    with pytest.raises(LookupError, match="target-session"):
        generate_incident_report_from_store(
            storage_path=str(storage_path),
            session_id="target-session",
            output_path=str(output_path),
        )

    assert not output_path.exists()


def test_service_raises_for_empty_store(tmp_path):
    storage_path = tmp_path / "empty-events.jsonl"

    with pytest.raises(LookupError, match="empty-session"):
        generate_incident_report_from_store(
            storage_path=str(storage_path),
            session_id="empty-session",
            output_path=str(tmp_path / "incident.json"),
        )
