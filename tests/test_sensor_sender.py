import httpx
import pytest

from telemetry.sensor.queue import SensorDeliveryQueue
from telemetry.sensor.sender import SensorHttpSender


class FakeResponse:
    def __init__(self, status_code=200, body=None):
        self.status_code = status_code
        self.body = body if body is not None else {"acknowledgements": []}

    def json(self):
        if isinstance(self.body, Exception):
            raise self.body
        return self.body


class FakeClient:
    def __init__(self, outcomes):
        self.outcomes = list(outcomes)
        self.calls = []
        self.closed = False

    def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    def close(self):
        self.closed = True


def make_events(*ids):
    return [{"event_id": event_id, "event_type": "test", "data": {}} for event_id in ids]


def make_sender(tmp_path, outcomes, **kwargs):
    queue = SensorDeliveryQueue(str(tmp_path / "queue.jsonl"))
    client = FakeClient(outcomes)
    delays = []
    sender = SensorHttpSender(
        queue=queue,
        collector_url="http://collector.local",
        sensor_id="sensor-test",
        sensor_token="secret-token",
        client=client,
        sleep=delays.append,
        base_backoff_seconds=1,
        max_backoff_seconds=10,
        **kwargs
    )
    return queue, client, delays, sender


def ack(*pairs):
    return FakeResponse(body={
        "acknowledgements": [
            {"event_id": event_id, "status": status}
            for event_id, status in pairs
        ]
    })


def test_success_acknowledges_and_removes_events(tmp_path):
    queue, client, delays, sender = make_sender(
        tmp_path, [ack(("a", "accepted"), ("b", "duplicate"))]
    )
    queue.enqueue_many(make_events("a", "b"))

    result = sender.flush()

    assert result["status"] == "delivered"
    assert result["acknowledged"] == 2
    assert queue.count() == 0
    url, kwargs = client.calls[0]
    assert url == "http://collector.local/api/v1/sensors/events"
    assert kwargs["headers"]["X-Morpheus-Sensor-ID"] == "sensor-test"
    assert kwargs["headers"]["X-Morpheus-Sensor-Token"] == "secret-token"
    assert len(kwargs["json"]["events"]) == 2
    assert delays == []


def test_network_error_retries_with_exponential_backoff(tmp_path):
    queue, client, delays, sender = make_sender(
        tmp_path,
        [
            httpx.ConnectError("offline"),
            FakeResponse(body={"acknowledgements": [
                {"event_id": "a", "status": "accepted"}
            ]}),
        ],
        max_attempts=3,
    )
    queue.enqueue_many(make_events("a"))

    result = sender.flush()

    assert result["status"] == "delivered"
    assert result["attempts"] == 2
    assert delays == [1.0]
    assert queue.count() == 0


def test_server_error_retries_and_keeps_queue_if_exhausted(tmp_path):
    queue, client, delays, sender = make_sender(
        tmp_path,
        [FakeResponse(503), FakeResponse(503), FakeResponse(503)],
        max_attempts=3,
    )
    queue.enqueue_many(make_events("a"))

    result = sender.flush()

    assert result["status"] == "pending"
    assert result["attempts"] == 3
    assert result["remaining"] == 1
    assert queue.pending()[0]["event_id"] == "a"
    assert delays == [1.0, 2.0]


def test_partial_ack_removes_only_acknowledged_events(tmp_path):
    queue, client, delays, sender = make_sender(
        tmp_path,
        [
            ack(("a", "accepted")),
            ack(("b", "duplicate")),
        ],
        max_attempts=3,
    )
    queue.enqueue_many(make_events("a", "b"))

    result = sender.flush()

    assert result["status"] == "delivered"
    assert result["acknowledged"] == 2
    assert queue.count() == 0
    assert len(client.calls) == 2
    assert [e["event_id"] for e in client.calls[1][1]["json"]["events"]] == ["b"]


def test_malformed_ack_does_not_remove_any_events(tmp_path):
    queue, client, delays, sender = make_sender(
        tmp_path,
        [FakeResponse(body={"unexpected": []})],
        max_attempts=1,
    )
    queue.enqueue_many(make_events("a"))

    result = sender.flush()

    assert result["status"] == "pending"
    assert queue.count() == 1


def test_ack_for_unsubmitted_event_is_rejected_atomically(tmp_path):
    queue, client, delays, sender = make_sender(
        tmp_path,
        [ack(("a", "accepted"), ("not-submitted", "accepted"))],
        max_attempts=1,
    )
    queue.enqueue_many(make_events("a", "b"))

    result = sender.flush()

    assert result["status"] == "pending"
    assert queue.count() == 2


def test_permanent_client_error_does_not_retry(tmp_path):
    queue, client, delays, sender = make_sender(
        tmp_path, [FakeResponse(401), ack(("a", "accepted"))], max_attempts=3
    )
    queue.enqueue_many(make_events("a"))

    result = sender.flush()

    assert result["status"] == "pending"
    assert result["attempts"] == 1
    assert len(client.calls) == 1
    assert queue.count() == 1
    assert delays == []


def test_batch_size_is_capped_at_collector_limit(tmp_path):
    with pytest.raises(ValueError):
        make_sender(tmp_path, [], batch_size=101)


def test_flush_sends_at_most_configured_batch_size(tmp_path):
    queue, client, delays, sender = make_sender(
        tmp_path, [ack(("a", "accepted"), ("b", "accepted"))], batch_size=2
    )
    queue.enqueue_many(make_events("a", "b", "c"))

    result = sender.flush()

    assert result["status"] == "delivered"
    assert result["remaining"] == 1
    assert queue.pending()[0]["event_id"] == "c"
    assert len(client.calls[0][1]["json"]["events"]) == 2


def test_empty_queue_does_not_make_http_request(tmp_path):
    queue, client, delays, sender = make_sender(tmp_path, [])

    result = sender.flush()

    assert result["status"] == "empty"
    assert result["attempts"] == 0
    assert client.calls == []
