from intelligence.campaign.detector import CampaignDetector
from intelligence.fingerprint.engine import FingerprintEngine
from intelligence.intent.classifier import IntentClassifier
from intelligence.session.model import ReconstructedSession


def build_session(
    session_id: str,
    source_ip: str,
    commands: list,
) -> ReconstructedSession:
    session = ReconstructedSession(
        session_id=session_id,
        source_ip=source_ip,
        protocol="ssh",
        client_version="SSH-2.0-OpenSSH_8.2p1",
        hassh="abc123",
        commands=commands,
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
