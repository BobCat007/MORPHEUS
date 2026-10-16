
"""Tests for the append-only MORPHEUS incident lifecycle."""

import pytest

from core.storage.event_store import EventStore
from incidents.service import (
    get_incident,
    list_incidents,
    update_incident_status,
)


def save_alert(storage_path, alert_id="alert-001", session_id="session-001"):
    store = EventStore(str(storage_path))
    store.save(
        {
            "event_type": "morpheus.alert.created",
            "source": "morpheus.alerting",
            "timestamp": "2026-10-16T10:00:00+00:00",
            "data": {
                "alert_id": alert_id,
                "session_id": session_id,
                "severity": "high",
                "risk_score": 75,
                "source_ip": "192.0.2.10",
                "title": "High-risk session detected",
                "description": "Synthetic test alert.",
            },
        }
    )


def test_list_incidents_reconstructs_incident_from_alert(tmp_path):
    storage_path = tmp_path / "events.jsonl"
    save_alert(storage_path)

    incidents = list_incidents(str(storage_path))

    assert len(incidents) == 1
    assert incidents[0]["incident_id"] == "MORPHEUS-INC-alert-001"
    assert incidents[0]["alert_id"] == "alert-001"
    assert incidents[0]["session_id"] == "session-001"
    assert incidents[0]["severity"] == "high"
    assert incidents[0]["risk_score"] == 75
    assert incidents[0]["status"] == "open"
    assert incidents[0]["history"] == []


def test_status_change_is_persisted_and_audited(tmp_path):
    storage_path = tmp_path / "events.jsonl"
    save_alert(storage_path)
    incident_id = "MORPHEUS-INC-alert-001"

    updated = update_incident_status(
        storage_path=str(storage_path),
        incident_id=incident_id,
        status="acknowledged",
        actor="analyst-1",
        note="Beginning triage.",
        changed_at="2026-10-16T10:05:00+00:00",
    )

    assert updated["status"] == "acknowledged"
    assert updated["updated_at"] == "2026-10-16T10:05:00+00:00"
    assert len(updated["history"]) == 1
    assert updated["history"][0] == {
        "timestamp": "2026-10-16T10:05:00+00:00",
        "from_status": "open",
        "to_status": "acknowledged",
        "actor": "analyst-1",
        "note": "Beginning triage.",
    }

    # The original alert remains intact and the change is a new event.
    records = EventStore(str(storage_path)).read_all()
    assert len(records) == 2
    assert records[0]["event_type"] == "morpheus.alert.created"
    assert records[1]["event_type"] == "morpheus.incident.status_changed"


def test_status_history_survives_reloading_and_can_reopen_incident(tmp_path):
    storage_path = tmp_path / "events.jsonl"
    save_alert(storage_path)
    incident_id = "MORPHEUS-INC-alert-001"

    update_incident_status(
        str(storage_path), incident_id, "investigating"
    )
    update_incident_status(
        str(storage_path), incident_id, "resolved"
    )
    reopened = update_incident_status(
        str(storage_path),
        incident_id,
        "open",
        actor="analyst-2",
        note="New evidence received.",
    )

    reloaded = get_incident(str(storage_path), incident_id)

    assert reopened["status"] == "open"
    assert reloaded["status"] == "open"
    assert len(reloaded["history"]) == 3
    assert [entry["to_status"] for entry in reloaded["history"]] == [
        "investigating",
        "resolved",
        "open",
    ]
    assert reloaded["history"][-1]["actor"] == "analyst-2"


def test_get_incident_rejects_unknown_id(tmp_path):
    with pytest.raises(LookupError, match="missing"):
        get_incident(
            str(tmp_path / "events.jsonl"),
            "missing",
        )


def test_status_update_rejects_invalid_status(tmp_path):
    storage_path = tmp_path / "events.jsonl"
    save_alert(storage_path)

    with pytest.raises(ValueError, match="Invalid status"):
        update_incident_status(
            str(storage_path),
            "MORPHEUS-INC-alert-001",
            "urgent",
        )


def test_status_update_rejects_redundant_status(tmp_path):
    storage_path = tmp_path / "events.jsonl"
    save_alert(storage_path)

    with pytest.raises(ValueError, match="already in status"):
        update_incident_status(
            str(storage_path),
            "MORPHEUS-INC-alert-001",
            "open",
        )


def test_list_incidents_returns_empty_list_for_empty_store(tmp_path):
    assert list_incidents(str(tmp_path / "events.jsonl")) == []
