from core.events.model import MorpheusEvent
from intelligence.session.reconstructor import SessionReconstructor


def make_event(event_type, data, timestamp="2026-10-17T10:00:00Z"):
    return MorpheusEvent(
        event_type=event_type,
        source="cowrie",
        data=data,
        timestamp=timestamp,
    )


def test_invalid_ip_does_not_replace_valid_source_ip():
    reconstructor = SessionReconstructor()

    reconstructor.process(make_event(
        "cowrie.session.connect",
        {
            "session": "session-1",
            "src_ip": "192.0.2.10",
            "protocol": "ssh",
        },
    ))
    reconstructor.process(make_event(
        "cowrie.session.connect",
        {
            "session": "session-1",
            "src_ip": "not-an-ip",
            "protocol": [],
        },
        timestamp="2026-10-17T10:01:00Z",
    ))

    session = reconstructor.get_session("session-1")
    assert session.source_ip == "192.0.2.10"
    assert session.protocol == "ssh"


def test_malformed_fields_are_ignored_without_crashing():
    reconstructor = SessionReconstructor()

    reconstructor.process(make_event(
        "cowrie.session.connect",
        {"session": ["invalid"], "src_ip": "192.0.2.1"},
    ))
    reconstructor.process(make_event(
        "cowrie.session.connect",
        {"session": "session-2", "src_ip": None, "protocol": 123},
    ))
    reconstructor.process(make_event(
        "cowrie.command.input",
        {"session": "session-2", "input": {"unexpected": "object"}},
    ))
    reconstructor.process(make_event(
        "cowrie.session.closed",
        {"session": "session-2", "duration_ms": True},
    ))

    session = reconstructor.get_session("session-2")
    assert session is not None
    assert session.source_ip is None
    assert session.protocol is None
    assert session.commands == []
    assert session.duration_ms is None


def test_valid_ipv4_ipv6_and_session_fields_are_preserved():
    reconstructor = SessionReconstructor()

    reconstructor.process(make_event(
        "cowrie.session.connect",
        {
            "session": "ipv4-session",
            "src_ip": "192.0.2.10",
            "protocol": "ssh",
        },
    ))
    reconstructor.process(make_event(
        "cowrie.session.connect",
        {
            "session": "ipv6-session",
            "src_ip": "2001:db8::1",
            "protocol": "ssh",
        },
    ))
    reconstructor.process(make_event(
        "cowrie.login.success",
        {"session": "ipv4-session", "username": "admin"},
    ))
    reconstructor.process(make_event(
        "cowrie.command.input",
        {"session": "ipv4-session", "input": "whoami"},
    ))
    reconstructor.process(make_event(
        "cowrie.session.closed",
        {"session": "ipv4-session", "duration_ms": 100},
    ))

    ipv4 = reconstructor.get_session("ipv4-session")
    ipv6 = reconstructor.get_session("ipv6-session")

    assert ipv4.source_ip == "192.0.2.10"
    assert ipv4.username == "admin"
    assert ipv4.authentication_success is True
    assert ipv4.commands == ["whoami"]
    assert ipv4.duration_ms == 100
    assert ipv6.source_ip == "2001:db8::1"


def test_unknown_event_does_not_create_a_session():
    reconstructor = SessionReconstructor()

    reconstructor.process(make_event(
        "unrecognized.event",
        {"session": "unknown-session"},
    ))

    assert reconstructor.get_all_sessions() == {}
