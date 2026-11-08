import httpx

from telemetry.sensor.runtime import (
    SensorHeartbeatClient,
    SensorRuntime,
)


class FakeResponse:
    def __init__(self, status_code=200):
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError(
                "request failed",
                request=httpx.Request("POST", "http://collector.test"),
                response=httpx.Response(self.status_code),
            )


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


class FakeSender:
    def __init__(self, outcomes=None):
        self.outcomes = list(outcomes or [])
        self.calls = 0

    def flush(self):
        self.calls += 1
        if self.outcomes:
            outcome = self.outcomes.pop(0)
            if isinstance(outcome, Exception):
                raise outcome
            return outcome
        return {"status": "empty", "remaining": 0}


def make_heartbeat(client):
    return SensorHeartbeatClient(
        collector_url="http://collector.test",
        sensor_id="sensor-test",
        sensor_token="test-secret",
        client=client,
    )


def test_heartbeat_sends_sensor_authentication_headers():
    client = FakeClient([FakeResponse()])
    heartbeat = make_heartbeat(client)

    result = heartbeat.heartbeat()

    assert result == {"status": "sent", "http_status": 200}
    url, kwargs = client.calls[0]
    assert url == "http://collector.test/api/v1/sensors/heartbeat"
    assert kwargs["headers"]["X-Morpheus-Sensor-ID"] == "sensor-test"
    assert kwargs["headers"]["X-Morpheus-Sensor-Token"] == "test-secret"


def test_runtime_sends_initial_heartbeat_and_flushes_queue():
    client = FakeClient([FakeResponse()])
    heartbeat = make_heartbeat(client)
    sender = FakeSender()
    clock = [100.0]

    runtime = SensorRuntime(
        sender,
        heartbeat,
        heartbeat_interval_seconds=30,
        poll_interval_seconds=5,
        clock=lambda: clock[0],
    )

    result = runtime.run_once()

    assert result["heartbeat"]["status"] == "sent"
    assert result["delivery"]["status"] == "empty"
    assert len(client.calls) == 1
    assert sender.calls == 1


def test_runtime_does_not_send_heartbeat_before_interval():
    client = FakeClient([FakeResponse()])
    heartbeat = make_heartbeat(client)
    sender = FakeSender()
    clock = [100.0]

    runtime = SensorRuntime(
        sender,
        heartbeat,
        heartbeat_interval_seconds=30,
        clock=lambda: clock[0],
    )

    runtime.run_once()
    clock[0] = 110.0
    result = runtime.run_once()

    assert result["heartbeat"]["status"] == "not_due"
    assert len(client.calls) == 1
    assert sender.calls == 2


def test_runtime_retries_heartbeat_after_next_interval():
    client = FakeClient([
        httpx.ConnectError("collector unavailable"),
        FakeResponse(),
    ])
    heartbeat = make_heartbeat(client)
    sender = FakeSender()
    clock = [100.0]

    runtime = SensorRuntime(
        sender,
        heartbeat,
        heartbeat_interval_seconds=30,
        clock=lambda: clock[0],
    )

    first = runtime.run_once()
    assert first["heartbeat"]["status"] == "failed"

    clock[0] = 131.0
    second = runtime.run_once()

    assert second["heartbeat"]["status"] == "sent"
    assert len(client.calls) == 2


def test_runtime_continues_event_delivery_if_heartbeat_fails():
    client = FakeClient([httpx.ConnectError("collector unavailable")])
    heartbeat = make_heartbeat(client)
    sender = FakeSender()

    runtime = SensorRuntime(sender, heartbeat)

    result = runtime.run_once()

    assert result["heartbeat"]["status"] == "failed"
    assert result["delivery"]["status"] == "empty"
    assert sender.calls == 1


def test_runtime_continues_after_unexpected_sender_error():
    client = FakeClient([FakeResponse()])
    heartbeat = make_heartbeat(client)
    sender = FakeSender([RuntimeError("temporary sender failure")])

    runtime = SensorRuntime(sender, heartbeat)

    result = runtime.run_once()

    assert result["heartbeat"]["status"] == "sent"
    assert result["delivery"]["status"] == "error"
    assert "temporary sender failure" in result["delivery"]["error"]


def test_heartbeat_client_closes_only_owned_client():
    client = FakeClient([])
    heartbeat = make_heartbeat(client)

    heartbeat.close()

    assert client.closed is False
