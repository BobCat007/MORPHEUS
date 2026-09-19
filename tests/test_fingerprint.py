from intelligence.fingerprint.engine import FingerprintEngine
from intelligence.session.model import ReconstructedSession


def test_identical_behavior_creates_same_fingerprint():
    engine = FingerprintEngine()

    session_one = ReconstructedSession(
        session_id="session-1",
        source_ip="10.0.0.1",
        protocol="ssh",
        client_version="SSH-2.0-OpenSSH_8.2p1",
        hassh="abc123",
        username="admin",
        authentication_success=True,
        commands=["ls", "whoami"],
        duration_ms=10000,
    )

    session_two = ReconstructedSession(
        session_id="session-2",
        source_ip="10.0.0.2",
        protocol="ssh",
        client_version="SSH-2.0-OpenSSH_8.2p1",
        hassh="abc123",
        username="admin",
        authentication_success=True,
        commands=["ls", "whoami"],
        duration_ms=20000,
    )

    fingerprint_one = engine.process(session_one)
    fingerprint_two = engine.process(session_two)

    assert fingerprint_one.fingerprint_id == fingerprint_two.fingerprint_id
    assert fingerprint_one.session_count == 2
    assert fingerprint_one.source_ips == ["10.0.0.1", "10.0.0.2"]
    assert fingerprint_one.command_count == 4
    assert fingerprint_one.successful_login_count == 2


def test_different_behavior_creates_different_fingerprint():
    engine = FingerprintEngine()

    session_one = ReconstructedSession(
        session_id="session-1",
        source_ip="10.0.0.1",
        protocol="ssh",
        client_version="SSH-2.0-OpenSSH_8.2p1",
        hassh="abc123",
        commands=["ls", "whoami"],
        duration_ms=10000,
    )

    session_two = ReconstructedSession(
        session_id="session-2",
        source_ip="10.0.0.2",
        protocol="ssh",
        client_version="SSH-2.0-OpenSSH_8.2p1",
        hassh="abc123",
        commands=["wget", "chmod", "./payload"],
        duration_ms=10000,
    )

    fingerprint_one = engine.process(session_one)
    fingerprint_two = engine.process(session_two)

    assert fingerprint_one.fingerprint_id != fingerprint_two.fingerprint_id


def test_average_session_duration():
    engine = FingerprintEngine()

    session_one = ReconstructedSession(
        session_id="session-1",
        source_ip="10.0.0.1",
        protocol="ssh",
        duration_ms=10000,
    )

    session_two = ReconstructedSession(
        session_id="session-2",
        source_ip="10.0.0.2",
        protocol="ssh",
        duration_ms=30000,
    )

    fingerprint = engine.process(session_one)
    engine.process(session_two)

    assert fingerprint.session_count == 2
    assert fingerprint.average_session_duration() == 20000.0
