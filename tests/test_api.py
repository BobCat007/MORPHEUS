
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
