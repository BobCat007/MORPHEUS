from intelligence.session.model import ReconstructedSession
from intelligence.timeline.reconstructor import TimelineReconstructor


def test_timeline_preserves_command_timestamps():
    session = ReconstructedSession(
        session_id="test-session",
        start_time="2026-09-18T18:43:25.000000Z",
        end_time="2026-09-18T18:44:04.000000Z",
    )

    session.add_command(
        command="ls",
        timestamp="2026-09-18T18:43:34.000000Z",
    )

    session.add_command(
        command="whoami",
        timestamp="2026-09-18T18:43:41.000000Z",
    )

    timeline = TimelineReconstructor().build(session)

    command_events = [
        event
        for event in timeline
        if event.event_type == "command"
    ]

    assert len(command_events) == 2

    assert command_events[0].command == "ls"
    assert command_events[0].timestamp == "2026-09-18T18:43:34.000000Z"

    assert command_events[1].command == "whoami"
    assert command_events[1].timestamp == "2026-09-18T18:43:41.000000Z"


def test_timeline_maps_commands_to_mitre():
    session = ReconstructedSession(
        session_id="test-session",
        start_time="2026-09-18T18:43:25.000000Z",
    )

    session.add_command(
        command="ls",
        timestamp="2026-09-18T18:43:34.000000Z",
    )

    session.add_command(
        command="whoami",
        timestamp="2026-09-18T18:43:41.000000Z",
    )

    timeline = TimelineReconstructor().build(session)

    command_events = [
        event
        for event in timeline
        if event.event_type == "command"
    ]

    assert command_events[0].technique_id == "T1083"
    assert command_events[0].technique_name == "File and Directory Discovery"

    assert command_events[1].technique_id == "T1033"
    assert command_events[1].technique_name == "System Owner/User Discovery"


def test_timeline_contains_session_boundaries():
    session = ReconstructedSession(
        session_id="test-session",
        start_time="2026-09-18T18:43:25.000000Z",
        end_time="2026-09-18T18:44:04.000000Z",
    )

    timeline = TimelineReconstructor().build(session)

    assert timeline[0].event_type == "session_started"
    assert timeline[0].timestamp == "2026-09-18T18:43:25.000000Z"

    assert timeline[-1].event_type == "session_ended"
    assert timeline[-1].timestamp == "2026-09-18T18:44:04.000000Z"
