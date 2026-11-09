import json

from fastapi.testclient import TestClient

from api.app import create_app
from core.events.bus import EventBus
from telemetry.cowrie.live import CowrieLogFollower
from telemetry.sensor.analysis_worker import SensorAnalysisWorker
from telemetry.sensor.queue import SensorDeliveryQueue
from telemetry.sensor.sender import SensorHttpSender


class SensorApiClientAdapter:
    """Adapt the API TestClient to the sensor sender's HTTP interface."""

    def __init__(self, client):
        self.client = client

    def post(self, url, **kwargs):
        return self.client.post(
            "/api/v1/sensors/events",
            json=kwargs["json"],
            headers=kwargs["headers"],
        )


def test_distributed_sensor_pipeline_and_worker_restart(tmp_path):
    sensor_id = "sensor-e2e"
    session_id = "e2e-session-001"

    cowrie_log = tmp_path / "cowrie.json"
    queue_path = tmp_path / "sensor-queue.jsonl"
    sensor_store_path = tmp_path / "sensor-events.jsonl"
    analysis_store_path = tmp_path / "analysis-events.jsonl"

    timestamps = [
        "2026-11-09T10:00:00+00:00",
        "2026-11-09T10:00:01+00:00",
        "2026-11-09T10:00:02+00:00",
        "2026-11-09T10:00:03+00:00",
        "2026-11-09T10:00:04+00:00",
        "2026-11-09T10:00:05+00:00",
    ]

    cowrie_events = [
        {
            "eventid": "cowrie.session.connect",
            "session": session_id,
            "src_ip": "192.0.2.10",
            "protocol": "ssh",
        },
        {
            "eventid": "cowrie.client.version",
            "session": session_id,
            "version": "SSH-2.0-OpenSSH_8.2p1",
        },
        {
            "eventid": "cowrie.client.kex",
            "session": session_id,
            "hassh": "e2e-test-hassh",
        },
        {
            "eventid": "cowrie.login.failed",
            "session": session_id,
            "username": "admin",
        },
        {
            "eventid": "cowrie.command.input",
            "session": session_id,
            "input": "whoami",
        },
        {
            "eventid": "cowrie.session.closed",
            "session": session_id,
            "duration_ms": 5000,
        },
    ]

    with cowrie_log.open("w", encoding="utf-8") as handle:
        for event, timestamp in zip(cowrie_events, timestamps):
            record = {
                "uuid": "cowrie-" + timestamp[-9:-1].replace(":", ""),
                "timestamp": timestamp,
                **event,
            }
            handle.write(json.dumps(record) + "\n")

    # 1. Cowrie JSONL -> parser -> event bus -> durable sensor queue.
    queue = SensorDeliveryQueue(str(queue_path))
    bus = EventBus()
    bus.subscribe(
        "cowrie.session.connect",
        lambda event: queue.enqueue(event.to_dict()),
    )
    bus.subscribe(
        "cowrie.client.version",
        lambda event: queue.enqueue(event.to_dict()),
    )
    bus.subscribe(
        "cowrie.client.kex",
        lambda event: queue.enqueue(event.to_dict()),
    )
    bus.subscribe(
        "cowrie.login.failed",
        lambda event: queue.enqueue(event.to_dict()),
    )
    bus.subscribe(
        "cowrie.command.input",
        lambda event: queue.enqueue(event.to_dict()),
    )
    bus.subscribe(
        "cowrie.session.closed",
        lambda event: queue.enqueue(event.to_dict()),
    )

    follower = CowrieLogFollower(
        str(cowrie_log),
        bus,
        start_at_end=False,
    )

    assert follower.poll_once() == len(cowrie_events)
    follower.close()
    assert queue.count() == len(cowrie_events)

    # 2. Sensor queue -> authenticated collector API -> persistent raw store.
    app = create_app(
        storage_path=str(tmp_path / "api-events.jsonl"),
        sensor_storage_path=str(sensor_store_path),
        sensor_tokens={sensor_id: "e2e-secret-token"},
    )

    with TestClient(app) as api_client:
        sender = SensorHttpSender(
            queue=queue,
            collector_url="http://testserver",
            sensor_id=sensor_id,
            sensor_token="e2e-secret-token",
            client=SensorApiClientAdapter(api_client),
            max_attempts=1,
        )

        delivery = sender.flush()

        assert delivery["status"] == "delivered"
        assert delivery["acknowledged"] == len(cowrie_events)
        assert queue.count() == 0

    raw_records = [
        json.loads(line)
        for line in sensor_store_path.read_text(encoding="utf-8").splitlines()
    ]
    assert len(raw_records) == len(cowrie_events)
    assert all(
        record["data"]["honeypot_id"] == sensor_id
        for record in raw_records
    )

    # 3. Central analysis worker -> persisted intelligence analysis.
    worker = SensorAnalysisWorker(
        str(sensor_store_path),
        str(analysis_store_path),
    )

    first_result = worker.process_available_events()

    assert first_result["events_processed"] == len(cowrie_events)
    assert first_result["sensors"] == 1
    assert first_result["newly_analyzed_sessions"] == 1

    analysis_records = [
        json.loads(line)
        for line in analysis_store_path.read_text(
            encoding="utf-8"
        ).splitlines()
    ]

    assert len(analysis_records) == 1

    analysis = analysis_records[0]
    assert analysis["event_type"] == "morpheus.intelligence.analysis"
    assert analysis["data"]["honeypot_id"] == sensor_id
    assert analysis["data"]["session"]["session_id"] == session_id
    assert analysis["data"]["session"]["commands"] == ["whoami"]

    # 4. Simulate a central worker restart and replay of raw stored events.
    restarted_worker = SensorAnalysisWorker(
        str(sensor_store_path),
        str(analysis_store_path),
    )

    restart_result = restarted_worker.process_available_events()

    assert restart_result["events_processed"] == len(cowrie_events)
    assert restart_result["newly_analyzed_sessions"] == 0

    final_analysis_records = [
        json.loads(line)
        for line in analysis_store_path.read_text(
            encoding="utf-8"
        ).splitlines()
    ]

    assert len(final_analysis_records) == 1
