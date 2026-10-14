import json

from telemetry.cowrie.pipeline import run_cowrie_pipeline


def test_pipeline_persists_raw_events_and_intelligence_analysis(tmp_path):
    log_path = tmp_path / "cowrie.json"
    storage_path = tmp_path / "events.jsonl"

    session_id = "pipeline-integration-session"

    raw_events = [
        {
            "eventid": "cowrie.session.connect",
            "timestamp": "2026-10-14T10:00:00+00:00",
            "session": session_id,
            "src_ip": "192.0.2.25",
            "protocol": "ssh",
        },
        {
            "eventid": "cowrie.client.version",
            "timestamp": "2026-10-14T10:00:01+00:00",
            "session": session_id,
            "version": "SSH-2.0-OpenSSH_8.2p1",
        },
        {
            "eventid": "cowrie.client.kex",
            "timestamp": "2026-10-14T10:00:02+00:00",
            "session": session_id,
            "hassh": "pipeline-integration-hassh",
        },
        {
            "eventid": "cowrie.login.failed",
            "timestamp": "2026-10-14T10:00:03+00:00",
            "session": session_id,
            "username": "admin",
        },
        {
            "eventid": "cowrie.command.input",
            "timestamp": "2026-10-14T10:00:04+00:00",
            "session": session_id,
            "input": "whoami",
        },
        {
            "eventid": "cowrie.command.input",
            "timestamp": "2026-10-14T10:00:05+00:00",
            "session": session_id,
            "input": "ls",
        },
        {
            "eventid": "cowrie.session.closed",
            "timestamp": "2026-10-14T10:00:06+00:00",
            "session": session_id,
            "duration_ms": 5000,
        },
    ]

    log_path.write_text(
        "".join(json.dumps(event) + "\n" for event in raw_events),
        encoding="utf-8",
    )

    processed_count = run_cowrie_pipeline(
        log_path=str(log_path),
        storage_path=str(storage_path),
    )

    stored_events = [
        json.loads(line)
        for line in storage_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]

    raw_stored_events = [
        event
        for event in stored_events
        if event["source"] == "cowrie"
    ]
    analysis_events = [
        event
        for event in stored_events
        if event["event_type"] == "morpheus.intelligence.analysis"
    ]

    assert processed_count == len(raw_events)
    assert len(raw_stored_events) == len(raw_events)
    assert len(analysis_events) == 1

    analysis = analysis_events[0]["data"]

    assert analysis["session"]["session_id"] == session_id
    assert analysis["session"]["source_ip"] == "192.0.2.25"
    assert analysis["session"]["commands"] == ["whoami", "ls"]
    assert analysis["fingerprint"]["session_count"] == 1
    assert analysis["risk_assessment"]["score"] > 0
    assert analysis["recommended_actions"]
'PY'
