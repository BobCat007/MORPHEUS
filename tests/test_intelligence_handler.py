from core.events.bus import EventBus
from core.events.model import MorpheusEvent
from core.events.validator import validate_event
from intelligence.handler import IntelligenceHandler


def make_event(event_type, data, timestamp):
    return MorpheusEvent(
        event_type=event_type,
        source="cowrie",
        data=data,
        timestamp=timestamp,
    )


def build_session_events():
    session_id = "integration-session-1"

    return [
        make_event(
            "cowrie.session.connect",
            {
                "session": session_id,
                "src_ip": "192.0.2.10",
                "protocol": "ssh",
            },
            "2026-10-14T10:00:00+00:00",
        ),
        make_event(
            "cowrie.client.version",
            {
                "session": session_id,
                "version": "SSH-2.0-OpenSSH_8.2p1",
            },
            "2026-10-14T10:00:01+00:00",
        ),
        make_event(
            "cowrie.client.kex",
            {
                "session": session_id,
                "hassh": "integration-hassh",
            },
            "2026-10-14T10:00:02+00:00",
        ),
        make_event(
            "cowrie.login.failed",
            {
                "session": session_id,
                "username": "admin",
            },
            "2026-10-14T10:00:03+00:00",
        ),
        make_event(
            "cowrie.command.input",
            {
                "session": session_id,
                "input": "whoami",
            },
            "2026-10-14T10:00:04+00:00",
        ),
        make_event(
            "cowrie.command.input",
            {
                "session": session_id,
                "input": "ls",
            },
            "2026-10-14T10:00:05+00:00",
        ),
        make_event(
            "cowrie.session.closed",
            {
                "session": session_id,
                "duration_ms": 5000,
            },
            "2026-10-14T10:00:06+00:00",
        ),
    ]


def test_completed_session_publishes_intelligence_analysis():
    event_bus = EventBus()
    handler = IntelligenceHandler(event_bus)
    published = []

    event_bus.subscribe(
        "morpheus.intelligence.analysis",
        published.append,
    )

    for event in build_session_events():
        handler.handle(event)

    assert len(published) == 1

    analysis_event = published[0]
    assert validate_event(analysis_event.to_dict()) is True
    assert analysis_event.source == "morpheus"

    data = analysis_event.data

    assert data["session"]["session_id"] == "integration-session-1"
    assert data["session"]["source_ip"] == "192.0.2.10"
    assert data["session"]["commands"] == ["whoami", "ls"]

    assert data["fingerprint"]["fingerprint_id"]
    assert data["fingerprint"]["session_count"] == 1

    assert {item["intent"] for item in data["intents"]} == {
        "discovery",
        "file_discovery",
    }

    technique_ids = {
        item["technique_id"]
        for item in data["mitre_techniques"]
    }
    assert "T1033" in technique_ids
    assert "T1083" in technique_ids

    assessment = data["risk_assessment"]
    assert assessment["session_id"] == "integration-session-1"
    assert assessment["score"] > 0
    assert assessment["severity"] in {
        "low",
        "medium",
        "high",
        "critical",
    }

    assert data["recommended_actions"]
    assert data["campaign"] is None


def test_duplicate_session_close_does_not_process_session_twice():
    event_bus = EventBus()
    handler = IntelligenceHandler(event_bus)
    published = []

    event_bus.subscribe(
        "morpheus.intelligence.analysis",
        published.append,
    )

    events = build_session_events()

    for event in events:
        handler.handle(event)

    duplicate_close = events[-1]
    handler.handle(duplicate_close)

    assert len(published) == 1
    assert handler.fingerprint_engine.get_all()
    assert len(handler.fingerprint_engine.get_all()) == 1

    fingerprint = next(
        iter(handler.fingerprint_engine.get_all().values())
    )
    assert fingerprint.session_count == 1
    assert fingerprint.command_count == 2
