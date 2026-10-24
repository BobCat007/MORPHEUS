import json

from core.events.model import MorpheusEvent
import telemetry.cowrie.live_pipeline as live_pipeline


def test_live_pipeline_wires_follower_and_persists_events(
    tmp_path, monkeypatch
):
    log_path = tmp_path / "cowrie.json"
    log_path.write_text("", encoding="utf-8")
    storage_path = tmp_path / "events.jsonl"

    class FakeFollower:
        def __init__(
            self,
            log_path,
            event_bus,
            poll_interval,
            start_at_end,
        ):
            self.event_bus = event_bus
            self.start_at_end = start_at_end

        def run(self, stop_event):
            assert self.start_at_end is True

            self.event_bus.publish(
                MorpheusEvent(
                    event_type="cowrie.session.connect",
                    source="cowrie",
                    data={"session": "test-session"},
                    timestamp="2026-10-15T12:00:00+00:00",
                )
            )

            self.event_bus.publish(
                MorpheusEvent(
                    event_type="morpheus.intelligence.analysis",
                    source="morpheus",
                    data={"session": {"session_id": "test-session"}},
                    timestamp="2026-10-15T12:00:00+00:00",
                )
            )

    monkeypatch.setattr(
        live_pipeline, "CowrieLogFollower", FakeFollower
    )

    from threading import Event

    live_pipeline.run_live_cowrie_pipeline(
        log_path=str(log_path),
        storage_path=str(storage_path),
        stop_event=Event(),
    )

    stored_records = [
        json.loads(line)
        for line in storage_path.read_text(encoding="utf-8").splitlines()
    ]

    stored_text = json.dumps(stored_records)
    assert "cowrie.session.connect" in stored_text
    assert "morpheus.intelligence.analysis" in stored_text
    assert "test-session" in stored_text


def test_live_pipeline_requires_explicit_controller_when_enabled(tmp_path):
    from threading import Event
    import pytest

    with pytest.raises(ValueError, match="requires an explicit controller"):
        live_pipeline.run_live_cowrie_pipeline(
            log_path=str(tmp_path / "cowrie.json"),
            storage_path=str(tmp_path / "events.jsonl"),
            stop_event=Event(),
            adaptive_deception_enabled=True,
        )


def test_live_pipeline_accepts_explicit_controller_when_enabled(
    tmp_path, monkeypatch
):
    from threading import Event
    import deception.control.factory as factory

    class FakeFollower:
        def __init__(self, log_path, event_bus, poll_interval, start_at_end):
            pass

        def run(self, stop_event):
            pass

    def forbidden_factory(*args, **kwargs):
        raise AssertionError("Production factory must not be called implicitly")

    monkeypatch.setattr(
        factory, "create_cowrie_deception_controller", forbidden_factory
    )
    monkeypatch.setattr(live_pipeline, "CowrieLogFollower", FakeFollower)

    live_pipeline.run_live_cowrie_pipeline(
        log_path=str(tmp_path / "cowrie.json"),
        storage_path=str(tmp_path / "events.jsonl"),
        stop_event=Event(),
        adaptive_deception_enabled=True,
        deception_controller=object(),
    )


def test_live_pipeline_processes_appended_cowrie_record(tmp_path):
    import time
    from threading import Event, Thread

    log_path = tmp_path / "cowrie.json"
    log_path.write_text("", encoding="utf-8")
    storage_path = tmp_path / "events.jsonl"
    stop_event = Event()
    errors = []

    def run_pipeline():
        try:
            live_pipeline.run_live_cowrie_pipeline(
                log_path=str(log_path),
                storage_path=str(storage_path),
                stop_event=stop_event,
                poll_interval=0.01,
                start_at_end=True,
            )
        except Exception as exc:
            errors.append(exc)

    thread = Thread(target=run_pipeline, daemon=True)
    thread.start()

    record = {
        "eventid": "cowrie.session.connect",
        "timestamp": "2026-10-15T12:00:00+00:00",
        "session": "live-integration-session",
        "src_ip": "192.0.2.25",
        "protocol": "ssh",
    }

    try:
        # Allow the follower to open the empty log at EOF first.
        time.sleep(0.1)

        with log_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record) + "\n")
            handle.flush()

        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            if storage_path.exists():
                contents = storage_path.read_text(encoding="utf-8")
                if "live-integration-session" in contents:
                    break
            if errors:
                raise errors[0]
            time.sleep(0.01)
        else:
            raise AssertionError("Live Cowrie event was not persisted")

    finally:
        stop_event.set()
        thread.join(timeout=2)

    assert not thread.is_alive(), "Live pipeline did not stop"
    assert not errors
    assert "cowrie.session.connect" in contents
