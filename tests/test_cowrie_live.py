import json

import pytest

from core.events.bus import EventBus
from telemetry.cowrie.live import CowrieLogFollower


def make_record(session, eventid="cowrie.session.connect"):
    return {
        "eventid": eventid,
        "timestamp": "2026-10-15T12:00:00+00:00",
        "session": session,
        "src_ip": "192.0.2.10",
        "protocol": "ssh",
    }


def append_record(path, record):
    with path.open("ab") as handle:
        handle.write(
            (json.dumps(record) + "\n").encode("utf-8")
        )


def test_follower_skips_existing_history_and_reads_new_events(tmp_path):
    log_path = tmp_path / "cowrie.json"
    log_path.write_text(
        json.dumps(make_record("historical")) + "\n",
        encoding="utf-8",
    )

    bus = EventBus()
    received = []
    bus.subscribe("cowrie.session.connect", received.append)

    follower = CowrieLogFollower(str(log_path), bus)

    try:
        assert follower.poll_once() == 0
        assert received == []

        append_record(log_path, make_record("new-session"))

        assert follower.poll_once() == 1
        assert len(received) == 1
        assert received[0].data["session"] == "new-session"
    finally:
        follower.close()


def test_follower_waits_for_a_complete_json_line(tmp_path):
    log_path = tmp_path / "cowrie.json"
    log_path.write_bytes(b"")

    bus = EventBus()
    received = []
    bus.subscribe("cowrie.session.connect", received.append)

    follower = CowrieLogFollower(str(log_path), bus)

    try:
        assert follower.poll_once() == 0

        record = json.dumps(make_record("partial-session")).encode("utf-8")
        with log_path.open("ab") as handle:
            handle.write(record[:20])

        assert follower.poll_once() == 0
        assert received == []

        with log_path.open("ab") as handle:
            handle.write(record[20:] + b"\n")

        assert follower.poll_once() == 1
        assert len(received) == 1
        assert received[0].data["session"] == "partial-session"
    finally:
        follower.close()


def test_follower_reads_new_file_after_log_rotation(tmp_path):
    log_path = tmp_path / "cowrie.json"
    rotated_path = tmp_path / "cowrie.json.1"
    log_path.write_bytes(b"")

    bus = EventBus()
    received = []
    bus.subscribe("cowrie.session.connect", received.append)

    follower = CowrieLogFollower(str(log_path), bus)

    try:
        assert follower.poll_once() == 0

        rotated_path.write_bytes(b"")
        append_record(rotated_path, make_record("rotated-session"))
        rotated_path.replace(log_path)

        assert follower.poll_once() == 1
        assert len(received) == 1
        assert received[0].data["session"] == "rotated-session"
    finally:
        follower.close()


def test_follower_rejects_nonpositive_poll_interval(tmp_path):
    with pytest.raises(ValueError, match="poll_interval"):
        CowrieLogFollower(
            str(tmp_path / "cowrie.json"),
            EventBus(),
            poll_interval=0,
        )
