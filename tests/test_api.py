"""Tests for the MORPHEUS HTTP API."""

import json

from fastapi.testclient import TestClient

from api.app import create_app


def _write_events(path, events):
    path.write_text(
        "".join(
            json.dumps(event) + "\n"
            for event in events
        ),
        encoding="utf-8",
    )


def _alert(
    alert_id="alert-api-1",
    severity="high",
    session_id="session-api-1",
):
    return {
        "event_type": "morpheus.alert.created",
        "source": "morpheus.alerting",
        "timestamp": "2026-10-16T10:00:00+00:00",
        "data": {
            "alert_id": alert_id,
            "session_id": session_id,
            "severity": severity,
            "risk_score": 75,
            "source_ip": "192.0.2.15",
            "title": "Test security alert",
            "description": "Synthetic API test alert.",
        },
    }


def _client(tmp_path, events=None):
    storage_path = tmp_path / "api-events.jsonl"
    _write_events(storage_path, events or [])
    app = create_app(str(storage_path), write_token="test-write-token")
    client = TestClient(app)
    client.headers.update({"X-Morpheus-Write-Token": "test-write-token"})
    return client, storage_path


def test_health_endpoint(tmp_path):
    client, _ = _client(tmp_path)

    response = client.get("/api/v1/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "service": "morpheus-api",
    }


def test_dashboard_summarizes_alerts_and_incidents(tmp_path):
    client, _ = _client(
        tmp_path,
        [
            _alert("alert-1", "high", "session-1"),
            _alert("alert-2", "critical", "session-2"),
            _alert("alert-3", "high", "session-3"),
        ],
    )

    response = client.get("/api/v1/dashboard")

    assert response.status_code == 200
    body = response.json()
    assert body["total_alerts"] == 3
    assert body["alerts_by_severity"]["high"] == 2
    assert body["alerts_by_severity"]["critical"] == 1
    assert body["total_incidents"] == 3
    assert body["incidents_by_status"]["open"] == 3
    assert len(body["latest_alerts"]) == 3


def test_alert_listing_filters_by_severity(tmp_path):
    client, _ = _client(
        tmp_path,
        [
            _alert("alert-high", "high"),
            _alert("alert-critical", "critical"),
        ],
    )

    response = client.get("/api/v1/alerts?severity=critical")

    assert response.status_code == 200
    body = response.json()
    assert body["total_matching"] == 1
    assert body["items"][0]["data"]["alert_id"] == "alert-critical"


def test_alert_listing_rejects_invalid_severity(tmp_path):
    client, _ = _client(tmp_path, [_alert()])

    response = client.get("/api/v1/alerts?severity=urgent")

    assert response.status_code == 400


def test_alert_listing_limits_results(tmp_path):
    client, _ = _client(
        tmp_path,
        [
            _alert("alert-1"),
            _alert("alert-2"),
            _alert("alert-3"),
        ],
    )

    response = client.get("/api/v1/alerts?limit=2")

    assert response.status_code == 200
    assert response.json()["count"] == 2
    assert response.json()["total_matching"] == 3


def test_incident_detail_and_status_update(tmp_path):
    client, storage_path = _client(
        tmp_path,
        [_alert("incident-alert", "high", "incident-session")],
    )
    incident_id = "MORPHEUS-INC-incident-alert"

    detail = client.get(
        "/api/v1/incidents/{}".format(incident_id)
    )
    assert detail.status_code == 200
    assert detail.json()["status"] == "open"

    update = client.patch(
        "/api/v1/incidents/{}/status".format(incident_id),
        json={
            "status": "acknowledged",
            "actor": "api-test",
            "note": "Investigating through the API",
        },
    )

    assert update.status_code == 200
    assert update.json()["status"] == "acknowledged"
    assert update.json()["history"][-1]["actor"] == "api-test"

    stored_lines = storage_path.read_text(
        encoding="utf-8"
    ).splitlines()
    assert len(stored_lines) == 2
    assert json.loads(stored_lines[-1])["event_type"] == (
        "morpheus.incident.status_changed"
    )


def test_incident_listing_filters_by_status(tmp_path):
    client, _ = _client(
        tmp_path,
        [
            _alert("incident-1", "high", "session-1"),
            _alert("incident-2", "critical", "session-2"),
        ],
    )

    incident_id = "MORPHEUS-INC-incident-1"
    response = client.patch(
        "/api/v1/incidents/{}/status".format(incident_id),
        json={"status": "investigating"},
    )
    assert response.status_code == 200

    response = client.get("/api/v1/incidents?status=investigating")

    assert response.status_code == 200
    assert response.json()["total_matching"] == 1
    assert response.json()["items"][0]["incident_id"] == incident_id


def test_unknown_incident_returns_404(tmp_path):
    client, _ = _client(tmp_path)

    response = client.get("/api/v1/incidents/unknown-incident")

    assert response.status_code == 404


def test_invalid_incident_status_returns_400(tmp_path):
    client, _ = _client(tmp_path, [_alert()])
    incident_id = "MORPHEUS-INC-alert-api-1"

    response = client.patch(
        "/api/v1/incidents/{}/status".format(incident_id),
        json={"status": "invalid"},
    )

    assert response.status_code == 400


def test_invalid_request_body_returns_422(tmp_path):
    client, _ = _client(tmp_path, [_alert()])
    incident_id = "MORPHEUS-INC-alert-api-1"

    response = client.patch(
        "/api/v1/incidents/{}/status".format(incident_id),
        json={"actor": "api-test"},
    )

    assert response.status_code == 422


def test_incident_update_rejects_missing_token(tmp_path):
    client, storage_path = _client(
        tmp_path, [_alert("auth-alert", "high", "auth-session")]
    )
    client.headers.pop("X-Morpheus-Write-Token", None)
    original_events = storage_path.read_text(encoding="utf-8")

    response = client.patch(
        "/api/v1/incidents/MORPHEUS-INC-auth-alert/status",
        json={"status": "acknowledged"},
    )

    assert response.status_code == 401
    assert storage_path.read_text(encoding="utf-8") == original_events


def test_incident_update_rejects_invalid_token(tmp_path):
    client, storage_path = _client(
        tmp_path, [_alert("auth-alert", "high", "auth-session")]
    )
    original_events = storage_path.read_text(encoding="utf-8")

    response = client.patch(
        "/api/v1/incidents/MORPHEUS-INC-auth-alert/status",
        headers={"X-Morpheus-Write-Token": "wrong-token"},
        json={"status": "acknowledged"},
    )

    assert response.status_code == 401
    assert storage_path.read_text(encoding="utf-8") == original_events


def test_incident_update_fails_closed_without_configured_token(tmp_path):
    storage_path = tmp_path / "unconfigured-events.jsonl"
    _write_events(storage_path, [_alert("auth-alert", "high", "auth-session")])
    client = TestClient(create_app(str(storage_path), write_token=""))

    response = client.patch(
        "/api/v1/incidents/MORPHEUS-INC-auth-alert/status",
        json={"status": "acknowledged"},
    )

    assert response.status_code == 503


def test_campaign_listing_returns_reconstructed_campaigns(
    tmp_path, monkeypatch
):
    from dataclasses import asdict
    import importlib

    from intelligence.campaign.model import AttackCampaign

    api_module = importlib.import_module("api.app")

    campaign = AttackCampaign(
        campaign_id="campaign-api-test",
        session_ids=["sensor-a:session-1", "sensor-b:session-2"],
        honeypot_ids=["sensor-a", "sensor-b"],
        source_ips=["198.51.100.42"],
        intents=["discovery"],
        phases=["reconnaissance"],
        correlation_reasons=["same_source_ip", "shared_commands"],
        confidence_score=70,
        confidence_factors={"same_source_ip": 30, "shared_commands": 40},
        first_seen="2026-11-07T09:00:00+00:00",
        last_seen="2026-11-07T10:00:00+00:00",
    )

    class FakeAggregator:
        def rebuild(self, events):
            assert len(events) == 1
            return [campaign]

    monkeypatch.setattr(
        api_module,
        "CrossHoneypotAggregator",
        FakeAggregator,
    )

    analysis_event = {
        "event_type": "morpheus.intelligence.analysis",
        "timestamp": "2026-11-07T10:00:00+00:00",
        "data": {
            "session": {"session_id": "session-1"},
            "risk_assessment": {"score": 50, "severity": "medium"},
        },
    }

    client, _ = _client(tmp_path, [analysis_event])

    response = client.get("/api/v1/campaigns")

    assert response.status_code == 200
    body = response.json()
    assert body["count"] == 1
    assert body["total_matching"] == 1
    assert body["items"][0] == asdict(campaign)


def test_campaign_listing_filters_by_honeypot(
    tmp_path, monkeypatch
):
    import importlib

    from intelligence.campaign.model import AttackCampaign

    api_module = importlib.import_module("api.app")

    sensor_a_campaign = AttackCampaign(
        campaign_id="campaign-a",
        honeypot_ids=["sensor-a", "sensor-b"],
        confidence_score=70,
    )
    sensor_c_campaign = AttackCampaign(
        campaign_id="campaign-c",
        honeypot_ids=["sensor-c"],
        confidence_score=40,
    )

    class FakeAggregator:
        def rebuild(self, events):
            return [sensor_a_campaign, sensor_c_campaign]

    monkeypatch.setattr(
        api_module,
        "CrossHoneypotAggregator",
        FakeAggregator,
    )

    analysis_event = {
        "event_type": "morpheus.intelligence.analysis",
        "timestamp": "2026-11-07T10:00:00+00:00",
        "data": {
            "session": {"session_id": "session-1"},
            "risk_assessment": {"score": 50, "severity": "medium"},
        },
    }

    client, _ = _client(tmp_path, [analysis_event])

    response = client.get("/api/v1/campaigns?honeypot_id=sensor-c")

    assert response.status_code == 200
    body = response.json()
    assert body["count"] == 1
    assert body["total_matching"] == 1
    assert body["items"][0]["campaign_id"] == "campaign-c"


def test_campaign_listing_respects_limit(tmp_path, monkeypatch):
    import importlib

    from intelligence.campaign.model import AttackCampaign

    api_module = importlib.import_module("api.app")

    class FakeAggregator:
        def rebuild(self, events):
            return [
                AttackCampaign(campaign_id="campaign-1"),
                AttackCampaign(campaign_id="campaign-2"),
                AttackCampaign(campaign_id="campaign-3"),
            ]

    monkeypatch.setattr(
        api_module,
        "CrossHoneypotAggregator",
        FakeAggregator,
    )

    analysis_event = {
        "event_type": "morpheus.intelligence.analysis",
        "timestamp": "2026-11-07T10:00:00+00:00",
        "data": {
            "session": {"session_id": "session-1"},
            "risk_assessment": {"score": 50, "severity": "medium"},
        },
    }

    client, _ = _client(tmp_path, [analysis_event])

    response = client.get("/api/v1/campaigns?limit=2")

    assert response.status_code == 200
    assert response.json()["count"] == 2
    assert response.json()["total_matching"] == 3

def _http_event(
    client_ip="198.51.100.10",
    method="GET",
    path="/admin",
    status_code=200,
    honeypot_id="http-sensor-a",
):
    return {
        "event_id": f"http-{path}-{status_code}",
        "event_type": "morpheus.http.request",
        "source": "morpheus.http",
        "timestamp": "2026-11-07T10:00:00+00:00",
        "data": {
            "honeypot_id": honeypot_id,
            "client_ip": client_ip,
            "method": method,
            "path": path,
            "status_code": status_code,
            "response_time_ms": 12.5,
        },
    }


def _http_client(tmp_path, events=None):
    cowrie_path = tmp_path / "cowrie-events.jsonl"
    http_path = tmp_path / "http-events.jsonl"

    _write_events(cowrie_path, [])
    _write_events(http_path, events or [])

    app = create_app(
        str(cowrie_path),
        write_token="test-write-token",
        http_storage_path=str(http_path),
    )

    client = TestClient(app)
    client.headers.update({
        "X-Morpheus-Write-Token": "test-write-token"
    })
    return client, http_path


def test_http_events_returns_empty_when_store_missing(tmp_path):
    cowrie_path = tmp_path / "cowrie-events.jsonl"
    _write_events(cowrie_path, [])

    app = create_app(
        str(cowrie_path),
        http_storage_path=str(tmp_path / "missing-http-events.jsonl"),
    )

    response = TestClient(app).get("/api/v1/http-events")

    assert response.status_code == 200
    assert response.json() == {
        "count": 0,
        "total_matching": 0,
        "items": [],
    }


def test_http_events_lists_only_http_events(tmp_path):
    client, _ = _http_client(
        tmp_path,
        [
            _http_event(),
            _http_event(
                client_ip="198.51.100.20",
                method="POST",
                path="/login",
                status_code=404,
            ),
            _alert(),
        ],
    )

    response = client.get("/api/v1/http-events")

    assert response.status_code == 200
    body = response.json()
    assert body["count"] == 2
    assert body["total_matching"] == 2
    assert all(
        item["event_type"] == "morpheus.http.request"
        for item in body["items"]
    )


def test_http_events_filters_by_source_ip(tmp_path):
    client, _ = _http_client(
        tmp_path,
        [
            _http_event(client_ip="198.51.100.10"),
            _http_event(client_ip="198.51.100.20", path="/login"),
        ],
    )

    response = client.get(
        "/api/v1/http-events?source_ip=198.51.100.20"
    )

    assert response.status_code == 200
    assert response.json()["total_matching"] == 1
    assert response.json()["items"][0]["data"]["path"] == "/login"


def test_http_events_filters_by_method_and_status(tmp_path):
    client, _ = _http_client(
        tmp_path,
        [
            _http_event(method="GET", status_code=200),
            _http_event(method="POST", status_code=404, path="/login"),
        ],
    )

    response = client.get(
        "/api/v1/http-events?method=POST&status_code=404"
    )

    assert response.status_code == 200
    assert response.json()["total_matching"] == 1
    assert response.json()["items"][0]["data"]["method"] == "POST"


def test_http_events_filters_by_honeypot(tmp_path):
    client, _ = _http_client(
        tmp_path,
        [
            _http_event(honeypot_id="sensor-a"),
            _http_event(honeypot_id="sensor-b", path="/login"),
        ],
    )

    response = client.get(
        "/api/v1/http-events?honeypot_id=sensor-b"
    )

    assert response.status_code == 200
    assert response.json()["total_matching"] == 1


def test_http_events_respects_limit(tmp_path):
    client, _ = _http_client(
        tmp_path,
        [
            _http_event(path="/one"),
            _http_event(path="/two"),
            _http_event(path="/three"),
        ],
    )

    response = client.get("/api/v1/http-events?limit=2")

    assert response.status_code == 200
    assert response.json()["count"] == 2
    assert response.json()["total_matching"] == 3

def _sensor_client(tmp_path):
    cowrie_storage_path = tmp_path / "cowrie-events.jsonl"
    sensor_storage_path = tmp_path / "sensor-events.jsonl"
    _write_events(cowrie_storage_path, [])
    _write_events(sensor_storage_path, [])

    app = create_app(
        storage_path=str(cowrie_storage_path),
        sensor_storage_path=str(sensor_storage_path),
        sensor_tokens={"sensor-a": "sensor-secret-a"},
    )

    return TestClient(app), cowrie_storage_path, sensor_storage_path

def _read_events(storage_path):
    import json
    from pathlib import Path

    path = Path(storage_path)

    if not path.exists():
        return []

    return [
        json.loads(line)
        for line in path.read_text().splitlines()
        if line.strip()
    ]

def _sensor_event(event_id="remote-event-1", honeypot_id=None):
    data = {
        "client_ip": "198.51.100.25",
        "method": "GET",
        "path": "/admin",
    }

    if honeypot_id is not None:
        data["honeypot_id"] = honeypot_id

    return {
        "event_id": event_id,
        "event_type": "morpheus.http.request",
        "source": "remote-sensor",
        "timestamp": "2026-11-07T10:00:00+00:00",
        "data": data,
    }


def test_sensor_ingestion_rejects_missing_credentials(tmp_path):
    client, _, _ = _sensor_client(tmp_path)

    response = client.post(
        "/api/v1/sensors/events",
        json={"events": [_sensor_event()]},
    )

    assert response.status_code == 401


def test_sensor_ingestion_rejects_invalid_token(tmp_path):
    client, _, _ = _sensor_client(tmp_path)

    response = client.post(
        "/api/v1/sensors/events",
        headers={
            "X-Morpheus-Sensor-ID": "sensor-a",
            "X-Morpheus-Sensor-Token": "wrong-token",
        },
        json={"events": [_sensor_event()]},
    )

    assert response.status_code == 401


def test_sensor_ingestion_accepts_authenticated_batch(tmp_path):
    client, cowrie_storage_path, sensor_storage_path = _sensor_client(tmp_path)

    response = client.post(
        "/api/v1/sensors/events",
        headers={
            "X-Morpheus-Sensor-ID": "sensor-a",
            "X-Morpheus-Sensor-Token": "sensor-secret-a",
        },
        json={
            "events": [
                _sensor_event("remote-1"),
                _sensor_event("remote-2"),
            ]
        },
    )

    assert response.status_code == 200

    body = response.json()
    assert body["status"] == "accepted"
    assert body["sensor_id"] == "sensor-a"
    assert body["accepted"] == 2

    stored = _read_events(str(sensor_storage_path))

    assert len(stored) == 2
    assert all(
        event["data"]["honeypot_id"] == "sensor-a"
        for event in stored
    )
    # Remote ingestion must never append to the Cowrie writer's event store.
    assert _read_events(str(cowrie_storage_path)) == []


def test_sensor_ingestion_rejects_sensor_identity_mismatch(tmp_path):
    client, cowrie_storage_path, sensor_storage_path = _sensor_client(tmp_path)

    response = client.post(
        "/api/v1/sensors/events",
        headers={
            "X-Morpheus-Sensor-ID": "sensor-a",
            "X-Morpheus-Sensor-Token": "sensor-secret-a",
        },
        json={
            "events": [
                _sensor_event("remote-1"),
                _sensor_event("remote-2", honeypot_id="sensor-b"),
            ]
        },
    )

    assert response.status_code == 422
    assert _read_events(str(cowrie_storage_path)) == []
    assert _read_events(str(sensor_storage_path)) == []


def test_sensor_ingestion_fails_when_credentials_unconfigured(tmp_path):
    storage_path = tmp_path / "cowrie-events.jsonl"
    sensor_storage_path = tmp_path / "sensor-events.jsonl"
    _write_events(storage_path, [])
    _write_events(sensor_storage_path, [])

    app = create_app(
        storage_path=str(storage_path),
        sensor_storage_path=str(sensor_storage_path),
    )
    client = TestClient(app)

    response = client.post(
        "/api/v1/sensors/events",
        headers={
            "X-Morpheus-Sensor-ID": "sensor-a",
            "X-Morpheus-Sensor-Token": "anything",
        },
        json={"events": [_sensor_event()]},
    )

    assert response.status_code == 503


def test_sensor_ingestion_acknowledges_duplicate_events(tmp_path):
    client, _, sensor_path = _sensor_client(tmp_path)

    headers = {
        "X-Morpheus-Sensor-ID": "sensor-a",
        "X-Morpheus-Sensor-Token": "sensor-secret-a",
    }

    event = _sensor_event("reliable-event-1")

    first = client.post(
        "/api/v1/sensors/events",
        headers=headers,
        json={"events": [event]},
    )

    assert first.status_code == 200
    assert first.json()["accepted"] == 1
    assert first.json()["duplicate"] == 0
    assert first.json()["acknowledgements"] == [
        {"event_id": "reliable-event-1", "status": "accepted"}
    ]

    second = client.post(
        "/api/v1/sensors/events",
        headers=headers,
        json={"events": [event]},
    )

    assert second.status_code == 200
    assert second.json()["accepted"] == 0
    assert second.json()["duplicate"] == 1
    assert second.json()["acknowledgements"] == [
        {"event_id": "reliable-event-1", "status": "duplicate"}
    ]

    assert len(_read_events(str(sensor_path))) == 1


def test_sensor_ingestion_deduplicates_within_same_batch(tmp_path):
    client, _, sensor_path = _sensor_client(tmp_path)

    response = client.post(
        "/api/v1/sensors/events",
        headers={
            "X-Morpheus-Sensor-ID": "sensor-a",
            "X-Morpheus-Sensor-Token": "sensor-secret-a",
        },
        json={
            "events": [
                _sensor_event("batch-duplicate"),
                _sensor_event("batch-duplicate"),
                _sensor_event("batch-new"),
            ]
        },
    )

    assert response.status_code == 200
    body = response.json()

    assert body["accepted"] == 2
    assert body["duplicate"] == 1
    assert len(_read_events(str(sensor_path))) == 2
    assert [item["status"] for item in body["acknowledgements"]] == [
        "accepted",
        "duplicate",
        "accepted",
    ]

def test_sensor_heartbeat_rejects_missing_credentials(tmp_path):
    client, _, _ = _sensor_client(tmp_path)

    response = client.post("/api/v1/sensors/heartbeat")

    assert response.status_code == 401


def test_sensor_heartbeat_rejects_invalid_token(tmp_path):
    client, _, _ = _sensor_client(tmp_path)

    response = client.post(
        "/api/v1/sensors/heartbeat",
        headers={
            "X-Morpheus-Sensor-ID": "sensor-a",
            "X-Morpheus-Sensor-Token": "wrong-token",
        },
    )

    assert response.status_code == 401


def test_sensor_heartbeat_updates_persistent_last_seen(tmp_path):
    import json

    client, _, sensor_storage_path = _sensor_client(tmp_path)

    response = client.post(
        "/api/v1/sensors/heartbeat",
        headers={
            "X-Morpheus-Sensor-ID": "sensor-a",
            "X-Morpheus-Sensor-Token": "sensor-secret-a",
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "recorded"
    assert body["sensor_id"] == "sensor-a"
    assert body["last_seen"]

    registry_path = sensor_storage_path.with_name("sensor-registry.json")
    registry = json.loads(registry_path.read_text())

    assert registry["sensors"]["sensor-a"]["last_seen"] == body["last_seen"]


def test_sensor_health_changes_from_offline_to_online(tmp_path):
    client, _, _ = _sensor_client(tmp_path)

    headers = {
        "X-Morpheus-Sensor-ID": "sensor-a",
        "X-Morpheus-Sensor-Token": "sensor-secret-a",
    }

    initial = client.get("/api/v1/sensors/health")

    assert initial.status_code == 200
    assert initial.json()["offline"] == 1
    assert initial.json()["online"] == 0

    heartbeat = client.post(
        "/api/v1/sensors/heartbeat",
        headers=headers,
    )

    assert heartbeat.status_code == 200

    updated = client.get("/api/v1/sensors/health")

    assert updated.status_code == 200
    assert updated.json()["online"] == 1
    assert updated.json()["offline"] == 0
    assert updated.json()["sensors"][0]["status"] == "online"

def test_sensor_health_marks_stale_sensor_offline(tmp_path):
    import json
    from datetime import datetime, timedelta, timezone

    client, _, sensor_storage_path = _sensor_client(tmp_path)

    registry_path = sensor_storage_path.with_name("sensor-registry.json")
    registry = json.loads(registry_path.read_text())

    stale_time = (datetime.now(timezone.utc) - timedelta(seconds=120)).isoformat()
    registry["sensors"]["sensor-a"]["last_seen"] = stale_time
    registry_path.write_text(json.dumps(registry))

    response = client.get("/api/v1/sensors/health")

    assert response.status_code == 200
    assert response.json()["offline"] == 1
    assert response.json()["online"] == 0
    assert response.json()["sensors"][0]["status"] == "offline"


def test_stale_sensor_recovers_after_new_heartbeat(tmp_path):
    import json
    from datetime import datetime, timedelta, timezone

    client, _, sensor_storage_path = _sensor_client(tmp_path)

    registry_path = sensor_storage_path.with_name("sensor-registry.json")
    registry = json.loads(registry_path.read_text())

    stale_time = (datetime.now(timezone.utc) - timedelta(seconds=120)).isoformat()
    registry["sensors"]["sensor-a"]["last_seen"] = stale_time
    registry_path.write_text(json.dumps(registry))

    stale_response = client.get("/api/v1/sensors/health")
    assert stale_response.json()["offline"] == 1

    heartbeat_response = client.post(
        "/api/v1/sensors/heartbeat",
        headers={
            "X-Morpheus-Sensor-ID": "sensor-a",
            "X-Morpheus-Sensor-Token": "sensor-secret-a",
        },
    )

    assert heartbeat_response.status_code == 200

    recovered_response = client.get("/api/v1/sensors/health")

    assert recovered_response.status_code == 200
    assert recovered_response.json()["online"] == 1
    assert recovered_response.json()["offline"] == 0
