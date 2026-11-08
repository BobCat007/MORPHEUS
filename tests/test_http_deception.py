import json

from fastapi.testclient import TestClient

from telemetry.http.app import create_http_app


def test_homepage_returns_fake_enterprise_portal(tmp_path):
    app = create_http_app(str(tmp_path / "http-events.jsonl"))

    response = TestClient(app).get("/")

    assert response.status_code == 200
    assert "Enterprise Application Portal" in response.text


def test_http_request_is_persisted(tmp_path):
    event_path = tmp_path / "http-events.jsonl"
    app = create_http_app(str(event_path))

    response = TestClient(app).get(
        "/admin",
        headers={"user-agent": "MORPHEUS-Test-Agent"},
    )

    assert response.status_code == 200

    records = [
        json.loads(line)
        for line in event_path.read_text().splitlines()
    ]

    assert len(records) == 1

    event = records[0]

    assert event["event_type"] == "morpheus.http.request"
    assert event["source"] == "morpheus.http"
    assert event["data"]["method"] == "GET"
    assert event["data"]["path"] == "/admin"
    assert event["data"]["status_code"] == 200
    assert event["data"]["user_agent"] == "MORPHEUS-Test-Agent"


def test_unknown_route_is_recorded(tmp_path):
    event_path = tmp_path / "http-events.jsonl"
    app = create_http_app(str(event_path))

    response = TestClient(app).get("/not-found")

    assert response.status_code == 404

    event = json.loads(event_path.read_text().splitlines()[0])

    assert event["data"]["path"] == "/not-found"
    assert event["data"]["status_code"] == 404


def test_health_endpoint_is_recorded(tmp_path):
    event_path = tmp_path / "http-events.jsonl"
    app = create_http_app(str(event_path))

    response = TestClient(app).get("/health")

    assert response.json() == {"status": "healthy"}
    assert event_path.exists()
