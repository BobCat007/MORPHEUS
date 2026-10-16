
"""Tests for MORPHEUS analyzed-session API endpoints."""

import json

from fastapi.testclient import TestClient

from api.app import create_app


def _write_events(path, events):
    path.write_text(
        "".join(json.dumps(event) + "\n" for event in events),
        encoding="utf-8",
    )


def _analysis(
    session_id="session-1",
    severity="medium",
    score=30,
):
    return {
        "event_id": "analysis-event-" + session_id,
        "event_type": "morpheus.intelligence.analysis",
        "source": "morpheus",
        "timestamp": "2026-10-16T10:00:00Z",
        "data": {
            "session": {
                "session_id": session_id,
                "source_ip": "192.0.2.20",
                "protocol": "ssh",
                "commands": ["whoami"],
            },
            "risk_assessment": {
                "session_id": session_id,
                "score": score,
                "severity": severity,
                "source_ip": "192.0.2.20",
                "factors": [],
            },
            "fingerprint": {
                "fingerprint_id": "fingerprint-test",
                "hassh": "test-hassh",
            },
            "intents": [
                {
                    "intent": "discovery",
                    "confidence": 1.0,
                    "evidence": ["whoami"],
                    "phase": "reconnaissance",
                }
            ],
            "mitre_techniques": [
                {
                    "technique_id": "T1033",
                    "technique_name": "System Owner/User Discovery",
                    "tactic": "Discovery",
                    "evidence": ["whoami"],
                }
            ],
        },
    }


def _client(tmp_path, events):
    path = tmp_path / "session-api-events.jsonl"
    _write_events(path, events)
    return TestClient(create_app(str(path)))


def test_session_listing_returns_analyzed_sessions(tmp_path):
    client = _client(
        tmp_path,
        [
            _analysis("session-medium", "medium", 30),
            _analysis("session-high", "high", 65),
        ],
    )

    response = client.get("/api/v1/sessions")

    assert response.status_code == 200
    body = response.json()
    assert body["count"] == 2
    assert body["total_matching"] == 2
    assert body["items"][0]["data"]["session"]["session_id"] == "session-high"
    assert body["items"][1]["data"]["session"]["session_id"] == "session-medium"


def test_session_listing_filters_by_severity(tmp_path):
    client = _client(
        tmp_path,
        [
            _analysis("session-medium", "medium", 30),
            _analysis("session-high", "high", 65),
            _analysis("session-critical", "critical", 90),
        ],
    )

    response = client.get("/api/v1/sessions?severity=medium")

    assert response.status_code == 200
    body = response.json()
    assert body["total_matching"] == 1
    assert body["items"][0]["data"]["session"]["session_id"] == "session-medium"


def test_session_listing_rejects_invalid_severity(tmp_path):
    client = _client(tmp_path, [_analysis()])

    response = client.get("/api/v1/sessions?severity=urgent")

    assert response.status_code == 400


def test_session_listing_respects_limit(tmp_path):
    client = _client(
        tmp_path,
        [
            _analysis("session-1"),
            _analysis("session-2"),
            _analysis("session-3"),
        ],
    )

    response = client.get("/api/v1/sessions?limit=2")

    assert response.status_code == 200
    assert response.json()["count"] == 2
    assert response.json()["total_matching"] == 3


def test_session_detail_returns_analysis_and_mitre_mapping(tmp_path):
    client = _client(
        tmp_path,
        [_analysis("session-detail", "medium", 30)],
    )

    response = client.get("/api/v1/sessions/session-detail")

    assert response.status_code == 200
    body = response.json()
    assert body["data"]["risk_assessment"]["score"] == 30
    assert body["data"]["fingerprint"]["fingerprint_id"] == "fingerprint-test"
    assert body["data"]["mitre_techniques"][0]["technique_id"] == "T1033"
    assert body["data"]["intents"][0]["intent"] == "discovery"


def test_unknown_session_returns_404(tmp_path):
    client = _client(tmp_path, [_analysis("existing-session")])

    response = client.get("/api/v1/sessions/missing-session")

    assert response.status_code == 404


def test_dashboard_includes_analyzed_session_counts(tmp_path):
    client = _client(
        tmp_path,
        [
            _analysis("session-medium", "medium", 30),
            _analysis("session-high", "high", 65),
            {
                "event_type": "cowrie.command.input",
                "timestamp": "2026-10-16T10:00:00Z",
                "data": {"command": "whoami"},
            },
        ],
    )

    response = client.get("/api/v1/dashboard")

    assert response.status_code == 200
    body = response.json()
    assert body["total_analyzed_sessions"] == 2
    assert body["sessions_by_severity"]["medium"] == 1
    assert body["sessions_by_severity"]["high"] == 1
    assert len(body["latest_sessions"]) == 2
