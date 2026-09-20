from intelligence.campaign.detector import CampaignDetector
from intelligence.fingerprint.engine import FingerprintEngine
from intelligence.intent.classifier import IntentClassifier
from intelligence.session.model import ReconstructedSession


def build_session(
    session_id: str,
    source_ip: str,
    commands: list,
    start_time: str = None,
    end_time: str = None,
) -> ReconstructedSession:
    session = ReconstructedSession(
        session_id=session_id,
        source_ip=source_ip,
        protocol="ssh",
        client_version="SSH-2.0-OpenSSH_8.2p1",
        hassh="abc123",
        commands=commands,
        start_time=start_time,
        end_time=end_time,
        duration_ms=30000,
    )

    return session


def test_same_source_ip_creates_campaign():
    detector = CampaignDetector()

    session_one = build_session(
        "session-1",
        "10.0.0.1",
        ["ls", "whoami"],
    )

    session_two = build_session(
        "session-2",
        "10.0.0.1",
        ["pwd", "hostname"],
    )

    campaign = detector.correlate(
        session_one,
        session_two,
    )

    assert campaign is not None
    assert "same_source_ip" in campaign.correlation_reasons
    assert campaign.session_ids == [
        "session-1",
        "session-2",
    ]


def test_same_hassh_creates_campaign():
    detector = CampaignDetector()

    session_one = build_session(
        "session-1",
        "10.0.0.1",
        ["ls"],
    )

    session_two = build_session(
        "session-2",
        "10.0.0.2",
        ["pwd"],
    )

    campaign = detector.correlate(
        session_one,
        session_two,
    )

    assert campaign is not None
    assert "same_hassh" in campaign.correlation_reasons


def test_shared_commands_create_campaign():
    detector = CampaignDetector()

    session_one = build_session(
        "session-1",
        "10.0.0.1",
        ["ls", "whoami"],
    )

    session_two = build_session(
        "session-2",
        "10.0.0.2",
        ["whoami", "pwd"],
    )

    campaign = detector.correlate(
        session_one,
        session_two,
    )

    assert campaign is not None
    assert "shared_commands" in campaign.correlation_reasons


def test_unrelated_sessions_do_not_create_campaign():
    detector = CampaignDetector()

    session_one = ReconstructedSession(
        session_id="session-1",
        source_ip="10.0.0.1",
        protocol="ssh",
        client_version="OpenSSH-8.2",
        hassh="hassh-one",
        commands=["ls"],
    )

    session_two = ReconstructedSession(
        session_id="session-2",
        source_ip="10.0.0.2",
        protocol="ftp",
        client_version="FTP-client",
        hassh="hassh-two",
        commands=["upload"],
    )

    campaign = detector.correlate(
        session_one,
        session_two,
    )

    assert campaign is None


def test_same_fingerprint_creates_campaign():
    detector = CampaignDetector()
    fingerprint_engine = FingerprintEngine()

    session_one = build_session(
        "session-1",
        "10.0.0.1",
        ["ls", "whoami"],
    )

    session_two = build_session(
        "session-2",
        "10.0.0.2",
        ["whoami", "ls"],
    )

    fingerprint_one = fingerprint_engine.process(
        session_one
    )

    fingerprint_two = fingerprint_engine.process(
        session_two
    )

    assert (
        fingerprint_one.fingerprint_id
        == fingerprint_two.fingerprint_id
    )

    campaign = detector.correlate(
        session_one,
        session_two,
        fingerprint_one,
        fingerprint_two,
    )

    assert campaign is not None
    assert "same_fingerprint" in campaign.correlation_reasons


def test_shared_intent_is_recorded():
    detector = CampaignDetector()
    classifier = IntentClassifier()

    session_one = build_session(
        "session-1",
        "10.0.0.1",
        ["whoami", "hostname"],
    )

    session_two = build_session(
        "session-2",
        "10.0.0.2",
        ["id", "uname -a"],
    )

    intents_one = classifier.classify(
        session=session_one
    )

    intents_two = classifier.classify(
        session=session_two
    )

    campaign = detector.correlate(
        session_one,
        session_two,
        intents_one=intents_one,
        intents_two=intents_two,
    )

    assert campaign is not None
    assert "shared_intent" in campaign.correlation_reasons
    assert "discovery" in campaign.intents
    assert "reconnaissance" in campaign.phases


def test_related_sessions_are_aggregated_into_one_campaign():
    detector = CampaignDetector()

    session_one = build_session(
        "session-1",
        "10.0.0.1",
        ["ls"],
    )

    session_two = build_session(
        "session-2",
        "10.0.0.1",
        ["whoami"],
    )

    session_three = build_session(
        "session-3",
        "10.0.0.1",
        ["pwd"],
    )

    campaign_one = detector.correlate(
        session_one,
        session_two,
    )

    campaign_two = detector.correlate(
        session_two,
        session_three,
    )

    assert campaign_one is not None
    assert campaign_two is not None

    assert campaign_one.campaign_id == campaign_two.campaign_id

    assert campaign_two.session_ids == [
        "session-1",
        "session-2",
        "session-3",
    ]

    assert len(detector.get_all()) == 1


def test_observe_session_automatically_correlates_with_previous_session():
    detector = CampaignDetector()

    session_one = build_session(
        "session-1",
        "10.0.0.1",
        ["ls", "whoami"],
    )

    session_two = build_session(
        "session-2",
        "10.0.0.1",
        ["pwd", "hostname"],
    )

    first_result = detector.observe(session_one)
    second_result = detector.observe(session_two)

    assert first_result is None
    assert second_result is not None

    assert second_result.session_ids == [
        "session-1",
        "session-2",
    ]

    assert "same_source_ip" in second_result.correlation_reasons


def test_observe_preserves_fingerprint_intelligence():
    detector = CampaignDetector()
    fingerprint_engine = FingerprintEngine()

    session_one = build_session(
        "session-1",
        "10.0.0.1",
        ["ls", "whoami"],
    )

    session_two = build_session(
        "session-2",
        "10.0.0.2",
        ["whoami", "ls"],
    )

    fingerprint_one = fingerprint_engine.process(
        session_one
    )

    fingerprint_two = fingerprint_engine.process(
        session_two
    )

    campaign = detector.observe(
        session_one,
        fingerprint=fingerprint_one,
    )

    assert campaign is None

    campaign = detector.observe(
        session_two,
        fingerprint=fingerprint_two,
    )

    assert campaign is not None
    assert "same_fingerprint" in campaign.correlation_reasons

    assert fingerprint_one.fingerprint_id in (
        campaign.fingerprint_ids
    )

    assert fingerprint_two.fingerprint_id in (
        campaign.fingerprint_ids
    )


def test_observe_preserves_intent_intelligence():
    detector = CampaignDetector()
    classifier = IntentClassifier()

    session_one = build_session(
        "session-1",
        "10.0.0.1",
        ["whoami", "hostname"],
    )

    session_two = build_session(
        "session-2",
        "10.0.0.2",
        ["id", "uname -a"],
    )

    intents_one = classifier.classify(
        session=session_one
    )

    intents_two = classifier.classify(
        session=session_two
    )

    campaign = detector.observe(
        session_one,
        intents=intents_one,
    )

    assert campaign is None

    campaign = detector.observe(
        session_two,
        intents=intents_two,
    )

    assert campaign is not None
    assert "shared_intent" in campaign.correlation_reasons

    assert "discovery" in campaign.intents
    assert "reconnaissance" in campaign.phases


def test_observe_same_session_id_is_idempotent():
    detector = CampaignDetector()

    session_one = build_session(
        "session-1",
        "10.0.0.1",
        ["ls", "whoami"],
    )

    session_two = build_session(
        "session-2",
        "10.0.0.1",
        ["pwd"],
    )

    first_result = detector.observe(session_one)

    assert first_result is None

    second_result = detector.observe(session_two)

    assert second_result is not None
    assert second_result.session_ids == [
        "session-1",
        "session-2",
    ]

    repeated_result = detector.observe(session_two)

    assert repeated_result is not None
    assert repeated_result.session_ids == [
        "session-1",
        "session-2",
    ]

    assert len(detector.sessions) == 2
    assert len(detector.get_all()) == 1


def test_related_campaigns_are_merged_when_new_evidence_connects_them():
    detector = CampaignDetector()

    session_one = build_session(
        "session-1",
        "10.0.0.1",
        ["ls"],
    )

    session_two = build_session(
        "session-2",
        "10.0.0.1",
        ["whoami"],
    )

    session_three = build_session(
        "session-3",
        "10.0.0.2",
        ["pwd"],
    )

    session_four = build_session(
        "session-4",
        "10.0.0.2",
        ["hostname"],
    )

    campaign_one = detector.correlate(
        session_one,
        session_two,
    )

    campaign_two = detector.correlate(
        session_three,
        session_four,
    )

    assert campaign_one is not None
    assert campaign_two is not None

    assert campaign_one.campaign_id != campaign_two.campaign_id
    assert len(detector.get_all()) == 2

    bridge_campaign = detector.correlate(
        session_two,
        session_three,
    )

    assert bridge_campaign is not None
    assert len(detector.get_all()) == 1

    assert bridge_campaign.session_ids == [
        "session-1",
        "session-2",
        "session-3",
        "session-4",
    ]


def test_campaign_records_first_and_last_seen_times():
    detector = CampaignDetector()

    session_one = build_session(
        "session-1",
        "10.0.0.1",
        ["ls"],
        start_time="2026-09-20T10:00:00+00:00",
        end_time="2026-09-20T10:05:00+00:00",
    )

    session_two = build_session(
        "session-2",
        "10.0.0.1",
        ["whoami"],
        start_time="2026-09-20T11:00:00+00:00",
        end_time="2026-09-20T11:10:00+00:00",
    )

    campaign = detector.correlate(
        session_one,
        session_two,
    )

    assert campaign is not None
    assert campaign.first_seen == "2026-09-20T10:00:00+00:00"
    assert campaign.last_seen == "2026-09-20T11:10:00+00:00"


def test_campaign_temporal_metadata_updates_when_campaign_grows():
    detector = CampaignDetector()

    session_one = build_session(
        "session-1",
        "10.0.0.1",
        ["ls"],
        start_time="2026-09-20T10:00:00+00:00",
        end_time="2026-09-20T10:05:00+00:00",
    )

    session_two = build_session(
        "session-2",
        "10.0.0.1",
        ["whoami"],
        start_time="2026-09-20T11:00:00+00:00",
        end_time="2026-09-20T11:10:00+00:00",
    )

    session_three = build_session(
        "session-3",
        "10.0.0.1",
        ["pwd"],
        start_time="2026-09-20T09:00:00+00:00",
        end_time="2026-09-20T12:00:00+00:00",
    )

    campaign = detector.correlate(
        session_one,
        session_two,
    )

    assert campaign is not None

    campaign = detector.correlate(
        session_two,
        session_three,
    )

    assert campaign is not None
    assert campaign.first_seen == "2026-09-20T09:00:00+00:00"
    assert campaign.last_seen == "2026-09-20T12:00:00+00:00"
