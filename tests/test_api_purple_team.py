"""Tests for the Purple Team simulation API."""

import json

import pytest
from fastapi.testclient import TestClient

from api.app import create_app


@pytest.fixture
def client(tmp_path):
    event_path = tmp_path / "events.jsonl"
    sensor_path = tmp_path / "sensor-events.jsonl"
    purple_path = tmp_path / "purple-team-runs.jsonl"

    app = create_app(
        storage_path=str(event_path),
        sensor_storage_path=str(sensor_path),
        purple_team_storage_path=str(purple_path),
    )
    return TestClient(app), event_path, purple_path


def test_list_purple_team_scenarios(client):
    test_client, _, _ = client

    response = test_client.get("/api/v1/purple-team/scenarios")

    assert response.status_code == 200
    body = response.json()
    assert body["count"] == 4
    assert {item["scenario_id"] for item in body["items"]} == {
        "discovery",
        "credential_access",
        "defense_evasion",
        "file_transfer",
    }


def test_run_purple_team_scenario_and_persist_result(client):
    test_client, event_path, purple_path = client

    response = test_client.post(
        "/api/v1/purple-team/runs",
        json={"scenario_id": "discovery"},
    )

    assert response.status_code == 200
    run = response.json()
    assert run["scenario_id"] == "discovery"
    assert run["status"] == "completed"
    assert run["source"] == "purple_team_simulation"
    assert run["coverage_percent"] == 100.0
    assert run["missed_techniques"] == []
    assert len(run["detected_techniques"]) > 0

    assert purple_path.exists()
    stored = json.loads(purple_path.read_text(encoding="utf-8").strip())
    assert stored["run_id"] == run["run_id"]

    # Purple Team data must not be written to the platform event store.
    assert not event_path.exists()


def test_list_and_get_purple_team_runs(client):
    test_client, _, _ = client

    created = test_client.post(
        "/api/v1/purple-team/runs",
        json={"scenario_id": "discovery"},
    ).json()

    listing = test_client.get("/api/v1/purple-team/runs?limit=10")
    assert listing.status_code == 200
    assert listing.json()["count"] == 1
    assert listing.json()["items"][0]["run_id"] == created["run_id"]

    detail = test_client.get(
        f"/api/v1/purple-team/runs/{created['run_id']}"
    )
    assert detail.status_code == 200
    assert detail.json()["run_id"] == created["run_id"]


def test_unknown_purple_team_scenario_returns_404(client):
    test_client, _, purple_path = client

    response = test_client.post(
        "/api/v1/purple-team/runs",
        json={"scenario_id": "not-a-real-scenario"},
    )

    assert response.status_code == 404
    assert not purple_path.exists()


def test_unknown_purple_team_run_returns_404(client):
    test_client, _, _ = client

    response = test_client.get("/api/v1/purple-team/runs/missing-run")

    assert response.status_code == 404


def test_purple_team_store_cannot_share_event_store_path(tmp_path):
    shared_path = tmp_path / "shared.jsonl"

    with pytest.raises(ValueError, match="separate store"):
        create_app(
            storage_path=str(shared_path),
            purple_team_storage_path=str(shared_path),
        )
