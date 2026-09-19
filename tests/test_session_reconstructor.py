from core.events.model import MorpheusEvent
from intelligence.session.reconstructor import SessionReconstructor


def test_session_reconstruction():
    reconstructor = SessionReconstructor()

    events = [
        MorpheusEvent(
            event_type="cowrie.session.connect",
            source="cowrie",
            timestamp="2026-09-18T18:43:25Z",
            data={
                "session": "test-session",
                "protocol": "ssh",
                "src_ip": "10.0.0.5",
            },
        ),
        MorpheusEvent(
            event_type="cowrie.login.success",
            source="cowrie",
            timestamp="2026-09-18T18:43:30Z",
            data={
                "session": "test-session",
                "username": "admin",
            },
        ),
        MorpheusEvent(
            event_type="cowrie.command.input",
            source="cowrie",
            timestamp="2026-09-18T18:43:35Z",
            data={
                "session": "test-session",
                "input": "whoami",
            },
        ),
        MorpheusEvent(
            event_type="cowrie.session.closed",
            source="cowrie",
            timestamp="2026-09-18T18:44:00Z",
            data={
                "session": "test-session",
                "duration_ms": 35000,
            },
        ),
    ]

    for event in events:
        reconstructor.process(event)

    session = reconstructor.get_session("test-session")

    assert session is not None
    assert session.source_ip == "10.0.0.5"
    assert session.protocol == "ssh"
    assert session.username == "admin"
    assert session.authentication_success is True
    assert session.commands == ["whoami"]
    assert session.command_count() == 1
    assert session.duration_ms == 35000
