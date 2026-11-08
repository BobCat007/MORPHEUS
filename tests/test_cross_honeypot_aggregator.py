from intelligence.campaign.aggregator import CrossHoneypotAggregator
from intelligence.campaign.persistence import qualified_session_id

from tests.test_campaign_persistence import make_session


def test_same_local_session_id_from_two_sensors_is_preserved():
    event_a = make_session(
        "shared-session",
        "192.0.2.10",
        "2026-10-16T10:00:00+00:00",
    )
    event_a["data"]["honeypot_id"] = "sensor-a"

    event_b = make_session(
        "shared-session",
        "192.0.2.10",
        "2026-10-16T10:01:00+00:00",
    )
    event_b["data"]["honeypot_id"] = "sensor-b"

    aggregator = CrossHoneypotAggregator()
    aggregator.rebuild([event_a, event_b])

    id_a = qualified_session_id("sensor-a", "shared-session")
    id_b = qualified_session_id("sensor-b", "shared-session")

    assert id_a != id_b
    assert id_a in aggregator.detector.sessions
    assert id_b in aggregator.detector.sessions
    assert len(aggregator.detector.sessions) == 2


def test_aggregator_correlates_sessions_across_sensors():
    event_a = make_session(
        "session-a",
        "192.0.2.20",
        "2026-10-16T10:00:00+00:00",
    )
    event_a["data"]["honeypot_id"] = "sensor-a"

    event_b = make_session(
        "session-b",
        "192.0.2.20",
        "2026-10-16T10:05:00+00:00",
    )
    event_b["data"]["honeypot_id"] = "sensor-b"

    aggregator = CrossHoneypotAggregator()
    campaigns = aggregator.rebuild([event_a, event_b])

    assert len(campaigns) == 1

    campaign = campaigns[0]
    assert set(campaign.honeypot_ids) == {"sensor-a", "sensor-b"}
    assert len(campaign.session_ids) == 2


def test_aggregator_uses_latest_event_per_sensor_session():
    old_event = make_session(
        "reused-session",
        "192.0.2.30",
        "2026-10-16T10:00:00+00:00",
    )
    old_event["data"]["honeypot_id"] = "sensor-a"

    newer_event = make_session(
        "reused-session",
        "192.0.2.40",
        "2026-10-16T11:00:00+00:00",
    )
    newer_event["data"]["honeypot_id"] = "sensor-a"

    aggregator = CrossHoneypotAggregator()
    aggregator.rebuild([old_event, newer_event])

    session_id = qualified_session_id("sensor-a", "reused-session")

    assert len(aggregator.detector.sessions) == 1
    assert (
        aggregator.detector.sessions[session_id].source_ip
        == "192.0.2.40"
    )


def test_aggregator_rebuild_is_repeatable():
    event = make_session(
        "session-a",
        "192.0.2.50",
        "2026-10-16T10:00:00+00:00",
    )
    event["data"]["honeypot_id"] = "sensor-a"

    aggregator = CrossHoneypotAggregator()

    first = aggregator.rebuild([event])
    first_ids = set(aggregator.detector.sessions)

    second = aggregator.rebuild([event])
    second_ids = set(aggregator.detector.sessions)

    assert first == second
    assert first_ids == second_ids
    assert len(second_ids) == 1


def test_aggregator_does_not_correlate_weak_evidence():
    event_a = make_session(
        "session-a",
        "192.0.2.60",
        "2026-10-16T10:00:00+00:00",
    )
    event_a["data"]["honeypot_id"] = "sensor-a"

    event_b = make_session(
        "session-b",
        "192.0.2.61",
        "2026-10-16T10:05:00+00:00",
    )
    event_b["data"]["honeypot_id"] = "sensor-b"

    # Remove distinctive behavior. Generic commands alone must not correlate.
    event_a["data"]["session"]["commands"] = ["whoami", "pwd"]
    event_b["data"]["session"]["commands"] = ["whoami", "pwd"]

    aggregator = CrossHoneypotAggregator()
    campaigns = aggregator.rebuild([event_a, event_b])

    assert campaigns == []


def test_aggregator_rebuilds_cross_sensor_campaign_from_shared_event_store(
    tmp_path,
):
    from core.storage.event_store import EventStore

    store = EventStore(str(tmp_path / "shared-events.jsonl"))

    event_a = make_session(
        "sensor-a-session",
        "192.0.2.70",
        "2026-10-16T10:00:00+00:00",
    )
    event_a["data"]["honeypot_id"] = "sensor-a"

    event_b = make_session(
        "sensor-b-session",
        "192.0.2.70",
        "2026-10-16T10:05:00+00:00",
    )
    event_b["data"]["honeypot_id"] = "sensor-b"

    store.save(event_a)
    store.save(event_b)

    persisted_events = store.read_all()

    aggregator = CrossHoneypotAggregator()
    campaigns = aggregator.rebuild(persisted_events)

    assert len(persisted_events) == 2
    assert len(campaigns) == 1
    assert set(campaigns[0].honeypot_ids) == {"sensor-a", "sensor-b"}
    assert len(campaigns[0].session_ids) == 2
