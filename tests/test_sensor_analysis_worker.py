import json
from types import SimpleNamespace

from telemetry.sensor.analysis_worker import (
    COWRIE_EVENT_TYPES,
    SensorAnalysisWorker,
)


def test_restored_sessions_are_not_counted_as_new(tmp_path, monkeypatch):
    sensor_path = tmp_path / "sensor-events.jsonl"
    analysis_path = tmp_path / "analysis-events.jsonl"

    event_type = next(iter(COWRIE_EVENT_TYPES))
    raw_event = {
        "event_id": "worker-restart-test-event",
        "event_type": event_type,
        "source": "test",
        "timestamp": "2026-11-08T10:00:00+00:00",
        "data": {
            "honeypot_id": "sensor-restart-test",
            "session": "existing-session",
        },
    }
    sensor_path.write_text(json.dumps(raw_event) + "\n")

    worker = SensorAnalysisWorker(sensor_path, analysis_path)

    class FakeBus:
        def publish(self, event):
            pass

    def create_restored_context(sensor_id):
        worker.contexts[sensor_id] = {
            "bus": FakeBus(),
            "handler": SimpleNamespace(
                processed_session_ids={"already-analyzed-session"}
            ),
        }

    monkeypatch.setattr(worker, "_create_sensor_context", create_restored_context)

    result = worker.process_available_events()

    assert result["sensors"] == 1
    assert result["events_processed"] == 1
    assert result["newly_analyzed_sessions"] == 0
