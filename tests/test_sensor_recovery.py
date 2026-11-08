import httpx
from fastapi.testclient import TestClient

from api.app import create_app
from telemetry.sensor.queue import SensorDeliveryQueue
from telemetry.sensor.sender import SensorHttpSender


SENSOR_ID = "sensor-recovery"
SENSOR_TOKEN = "recovery-test-secret"


def make_event(event_id):
    return {
        "event_id": event_id,
        "event_type": "morpheus.http.request",
        "source": "remote-sensor",
        "timestamp": "2026-11-08T10:00:00+00:00",
        "data": {
            "client_ip": "192.0.2.10",
            "method": "GET",
            "path": "/recovery-test",
        },
    }


class FailingClient:
    def post(self, *args, **kwargs):
        raise httpx.ConnectError("simulated collector outage")


class FakeClientAdapter:
    def __init__(self, client):
        self.client = client

    def post(self, url, **kwargs):
        return self.client.post(url, **kwargs)


def make_app(tmp_path):
    return create_app(
        storage_path=str(tmp_path / "cowrie-events.jsonl"),
        http_storage_path=str(tmp_path / "http-events.jsonl"),
        sensor_storage_path=str(tmp_path / "sensor-events.jsonl"),
        sensor_tokens={SENSOR_ID: SENSOR_TOKEN},
    )


def test_sender_recovers_queued_events_after_restart(tmp_path):
    queue_path = tmp_path / "sender-queue.jsonl"

    # First sender experiences an outage.
    first_queue = SensorDeliveryQueue(queue_path)
    first_queue.enqueue(make_event("recovery-event-1"))

    failed_sender = SensorHttpSender(
        queue=first_queue,
        collector_url="http://collector.test",
        sensor_id=SENSOR_ID,
        sensor_token=SENSOR_TOKEN,
        max_attempts=1,
        client=FailingClient(),
        sleep=lambda _: None,
    )

    result = failed_sender.flush()

    assert result["acknowledged"] == 0
    assert first_queue.count() == 1

    # Simulate sender restart by reconstructing the queue and sender.
    recovered_queue = SensorDeliveryQueue(queue_path)

    app = make_app(tmp_path)
    with TestClient(app) as api_client:
        recovered_sender = SensorHttpSender(
            queue=recovered_queue,
            collector_url="http://collector.test",
            sensor_id=SENSOR_ID,
            sensor_token=SENSOR_TOKEN,
            max_attempts=1,
            client=FakeClientAdapter(api_client),
            sleep=lambda _: None,
        )

        recovered_result = recovered_sender.flush()

    assert recovered_result["status"] == "delivered"
    assert recovered_result["acknowledged"] == 1
    assert recovered_queue.count() == 0

    stored = (tmp_path / "sensor-events.jsonl").read_text().splitlines()
    assert len(stored) == 1
    assert '"event_id": "recovery-event-1"' in stored[0]


def test_collector_restart_preserves_duplicate_detection(tmp_path):
    event = make_event("collector-restart-event")

    # First collector accepts and persists the event.
    first_app = make_app(tmp_path)
    with TestClient(first_app) as first_client:
        first_response = first_client.post(
            "/api/v1/sensors/events",
            headers={
                "X-Morpheus-Sensor-ID": SENSOR_ID,
                "X-Morpheus-Sensor-Token": SENSOR_TOKEN,
            },
            json={"events": [event]},
        )

    assert first_response.status_code == 200
    assert first_response.json()["acknowledgements"][0]["status"] == "accepted"

    # Recreate the collector with the same event and registry paths.
    second_app = make_app(tmp_path)
    with TestClient(second_app) as second_client:
        second_response = second_client.post(
            "/api/v1/sensors/events",
            headers={
                "X-Morpheus-Sensor-ID": SENSOR_ID,
                "X-Morpheus-Sensor-Token": SENSOR_TOKEN,
            },
            json={"events": [event]},
        )

    assert second_response.status_code == 200
    assert second_response.json()["acknowledgements"][0]["status"] == "duplicate"

    stored = (tmp_path / "sensor-events.jsonl").read_text().splitlines()
    assert len(stored) == 1
