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


def test_command_intervals_are_recorded():
    engine = FingerprintEngine()

    session = ReconstructedSession(
        session_id="session-1",
        protocol="ssh",
        commands=["ls", "whoami", "pwd"],
    )

    session.add_command(
        command="ls",
        timestamp="2026-09-18T18:43:34.000000Z",
    )

    session.add_command(
        command="whoami",
        timestamp="2026-09-18T18:43:39.000000Z",
    )

    session.add_command(
        command="pwd",
        timestamp="2026-09-18T18:43:47.000000Z",
    )

    fingerprint = engine.process(session)

    assert fingerprint.command_intervals_ms == [
        5000,
        8000,
    ]

    assert fingerprint.average_command_interval() == 6500.0


def test_unique_commands():
    engine = FingerprintEngine()

    session = ReconstructedSession(
        session_id="session-1",
        protocol="ssh",
        commands=["ls", "whoami", "ls", "pwd", "whoami"],
    )

    fingerprint = engine.process(session)

    assert fingerprint.unique_commands() == [
        "ls",
        "whoami",
        "pwd",
    ]


def test_commands_per_minute():
    engine = FingerprintEngine()

    session = ReconstructedSession(
        session_id="session-1",
        protocol="ssh",
        commands=["ls", "whoami", "pwd", "hostname"],
        duration_ms=60000,
    )

    fingerprint = engine.process(session)

    assert fingerprint.commands_per_minute() == 4.0

