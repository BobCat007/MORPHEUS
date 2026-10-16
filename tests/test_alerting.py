"""Tests for MORPHEUS alert generation and persistence."""

import pytest

from alerts.engine import AlertEngine
from alerts.handler import (
    ALERT_EVENT_TYPE,
    ANALYSIS_EVENT_TYPE,
    AlertingHandler,
)
from core.events.bus import EventBus
from core.events.model import MorpheusEvent
from core.storage.event_store import EventStore
from core.storage.handler import EventStorageHandler


def make_analysis(session_id="session-1", severity="high", score=70):
    """Build representative intelligence analysis data."""

    return {
        "session": {
            "session_id": session_id,
            "source_ip": "192.0.2.10",
            "protocol": "ssh",
        },
        "risk_assessment": {
            "session_id": session_id,
            "source_ip": "192.0.2.10",
            "score": score,
            "severity": severity,
            "factors": [
                {
                    "name": "intent_execution",
                    "score": 20,
                    "category": "behavior",
                    "evidence": ["suspicious command"],
                }
            ],
        },
    }


def make_analysis_event(analysis):
    return MorpheusEvent(
        event_type=ANALYSIS_EVENT_TYPE,
        source="morpheus",
        data=analysis,
        timestamp="2026-10-16T12:00:00+00:00",
    )


def make_pipeline(tmp_path, minimum_severity="high"):
    """Build an event bus with analysis and alert persistence."""

    event_bus = EventBus()
    event_store = EventStore(str(tmp_path / "events.jsonl"))
    storage_handler = EventStorageHandler(event_store)

    event_bus.subscribe(ANALYSIS_EVENT_TYPE, storage_handler.handle)
    event_bus.subscribe(ALERT_EVENT_TYPE, storage_handler.handle)

    alerting_handler = AlertingHandler(
        event_bus=event_bus,
        event_store=event_store,
        engine=AlertEngine(minimum_severity=minimum_severity),
    )
    event_bus.subscribe(ANALYSIS_EVENT_TYPE, alerting_handler.handle)

    return event_bus, event_store, alerting_handler


def get_alerts(event_store):
    return [
        event
        for event in event_store.read_all()
        if event.get("event_type") == ALERT_EVENT_TYPE
    ]


@pytest.mark.parametrize(
    ("severity", "score"),
    [
        ("low", 10),
        ("medium", 30),
    ],
)
def test_default_threshold_ignores_low_and_medium_risk(
    tmp_path, severity, score
):
    event_bus, event_store, _ = make_pipeline(tmp_path)

    event_bus.publish(
        make_analysis_event(make_analysis(severity=severity, score=score))
    )

    assert get_alerts(event_store) == []


def test_high_risk_analysis_creates_persisted_alert(tmp_path):
    event_bus, event_store, _ = make_pipeline(tmp_path)

    event_bus.publish(make_analysis_event(make_analysis()))

    alerts = get_alerts(event_store)

    assert len(alerts) == 1
    alert = alerts[0]["data"]

    assert alert["session_id"] == "session-1"
    assert alert["severity"] == "high"
    assert alert["risk_score"] == 70
    assert alert["source_ip"] == "192.0.2.10"
    assert alert["previous_severity"] is None
    assert alert["risk_factors"][0]["name"] == "intent_execution"


def test_repeated_high_risk_analysis_does_not_duplicate_alert(tmp_path):
    event_bus, event_store, _ = make_pipeline(tmp_path)

    event_bus.publish(make_analysis_event(make_analysis()))
    event_bus.publish(make_analysis_event(make_analysis()))

    assert len(get_alerts(event_store)) == 1


def test_critical_risk_escalation_creates_new_alert(tmp_path):
    event_bus, event_store, _ = make_pipeline(tmp_path)

    event_bus.publish(
        make_analysis_event(make_analysis(severity="high", score=70))
    )
    event_bus.publish(
        make_analysis_event(make_analysis(severity="critical", score=90))
    )

    alerts = get_alerts(event_store)

    assert len(alerts) == 2
    assert alerts[0]["data"]["severity"] == "high"
    assert alerts[1]["data"]["severity"] == "critical"
    assert alerts[1]["data"]["previous_severity"] == "high"


def test_existing_alerts_prevent_duplicates_after_restart(tmp_path):
    event_bus, event_store, _ = make_pipeline(tmp_path)
    event_bus.publish(make_analysis_event(make_analysis()))

    # A new handler should recover deduplication state from the event store.
    restarted_bus = EventBus()
    restarted_storage = EventStorageHandler(event_store)
    restarted_bus.subscribe(ANALYSIS_EVENT_TYPE, restarted_storage.handle)
    restarted_bus.subscribe(ALERT_EVENT_TYPE, restarted_storage.handle)

    restarted_handler = AlertingHandler(
        restarted_bus,
        event_store,
        AlertEngine(),
    )
    restarted_bus.subscribe(ANALYSIS_EVENT_TYPE, restarted_handler.handle)

    restarted_bus.publish(make_analysis_event(make_analysis()))

    assert len(get_alerts(event_store)) == 1


def test_medium_threshold_can_be_configured(tmp_path):
    event_bus, event_store, _ = make_pipeline(
        tmp_path,
        minimum_severity="medium",
    )

    event_bus.publish(
        make_analysis_event(make_analysis(severity="medium", score=30))
    )

    alerts = get_alerts(event_store)

    assert len(alerts) == 1
    assert alerts[0]["data"]["severity"] == "medium"


def test_invalid_threshold_is_rejected():
    with pytest.raises(ValueError, match="minimum_severity"):
        AlertEngine(minimum_severity="urgent")


def test_incomplete_analysis_does_not_create_alert(tmp_path):
    event_bus, event_store, _ = make_pipeline(tmp_path)

    event_bus.publish(
        make_analysis_event({"session": {"session_id": "session-1"}})
    )

    assert get_alerts(event_store) == []
