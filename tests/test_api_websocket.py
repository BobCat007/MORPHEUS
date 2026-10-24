import json
import time

from fastapi.testclient import TestClient

from api.app import create_app


def test_websocket_stream_receives_new_jsonl_event(tmp_path):
    storage = tmp_path / "events.jsonl"
    storage.write_text("", encoding="utf-8")
    client = TestClient(create_app(str(storage)))

    with client.websocket_connect("/api/v1/stream") as websocket:
        assert websocket.receive_json() == {"type": "stream.connected"}

        event = {
            "event_type": "morpheus.alert.created",
            "timestamp": "2026-10-21T12:00:00+00:00",
            "data": {"alert_id": "WS-TEST-1", "severity": "high"},
        }
        with storage.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event) + "\n")
            handle.flush()

        received = websocket.receive_json()
        assert received["event_type"] == "morpheus.alert.created"
        assert received["data"]["alert_id"] == "WS-TEST-1"


def test_websocket_stream_does_not_replay_existing_history(tmp_path):
    storage = tmp_path / "events.jsonl"
    storage.write_text(
        json.dumps({"event_type": "old.event", "data": {}}) + "\n",
        encoding="utf-8",
    )
    client = TestClient(create_app(str(storage)))

    with client.websocket_connect("/api/v1/stream") as websocket:
        assert websocket.receive_json() == {"type": "stream.connected"}
        # The stream starts at EOF. Append a fresh record and verify it is next.
        event = {"event_type": "new.event", "data": {"id": 2}}
        with storage.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event) + "\n")
            handle.flush()

        received = websocket.receive_json()
        assert received["event_type"] == "new.event"


def test_websocket_route_is_registered():
    app = create_app(":memory:")
    assert any(
        getattr(route, "path", None) == "/api/v1/stream"
        and getattr(route, "endpoint", None) is not None
        for route in app.routes
    )
