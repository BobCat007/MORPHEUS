import json

import pytest

from core.security.sensor_registry import (
    SensorAlreadyExists,
    SensorNotFound,
    SensorRegistry,
)


def test_register_generates_token_and_stores_only_hash(tmp_path):
    path = tmp_path / "registry.json"
    registry = SensorRegistry(path)

    token = registry.register("sensor-a")

    assert len(token) >= 40
    assert registry.verify("sensor-a", token)
    assert not registry.verify("sensor-a", "wrong-token")

    saved = json.loads(path.read_text())
    record = saved["sensors"]["sensor-a"]

    assert record["status"] == "active"
    assert record["token_hash"] != token
    assert token not in path.read_text()


def test_duplicate_registration_is_rejected(tmp_path):
    registry = SensorRegistry(tmp_path / "registry.json")
    registry.register("sensor-a")

    with pytest.raises(SensorAlreadyExists):
        registry.register("sensor-a")


def test_registry_persists_across_instances(tmp_path):
    path = tmp_path / "registry.json"
    first = SensorRegistry(path)
    token = first.register("sensor-a")

    second = SensorRegistry(path)

    assert second.verify("sensor-a", token)


def test_token_rotation_invalidates_old_token(tmp_path):
    registry = SensorRegistry(tmp_path / "registry.json")
    old_token = registry.register("sensor-a")

    new_token = registry.rotate("sensor-a")

    assert new_token != old_token
    assert not registry.verify("sensor-a", old_token)
    assert registry.verify("sensor-a", new_token)


def test_revocation_invalidates_token(tmp_path):
    registry = SensorRegistry(tmp_path / "registry.json")
    token = registry.register("sensor-a")

    registry.revoke("sensor-a")

    assert not registry.verify("sensor-a", token)
    assert registry.list_sensors() == [
        {"sensor_id": "sensor-a", "status": "revoked"}
    ]


def test_rotate_unknown_sensor_fails(tmp_path):
    registry = SensorRegistry(tmp_path / "registry.json")

    with pytest.raises(SensorNotFound):
        registry.rotate("unknown")


def test_revoke_unknown_sensor_fails(tmp_path):
    registry = SensorRegistry(tmp_path / "registry.json")

    with pytest.raises(SensorNotFound):
        registry.revoke("unknown")


def test_invalid_sensor_id_is_rejected(tmp_path):
    registry = SensorRegistry(tmp_path / "registry.json")

    with pytest.raises(ValueError):
        registry.register("../invalid")


def test_legacy_tokens_are_migrated_as_hashes(tmp_path):
    path = tmp_path / "registry.json"
    registry = SensorRegistry(
        path,
        initial_tokens={"legacy-sensor": "legacy-secret"},
    )

    assert registry.verify("legacy-sensor", "legacy-secret")
    assert "legacy-secret" not in path.read_text()
