import pytest

from telemetry.sensor.process import required_env, run_sensor


def test_required_env_returns_value(monkeypatch):
    monkeypatch.setenv("MORPHEUS_TEST_VALUE", "configured")
    assert required_env("MORPHEUS_TEST_VALUE") == "configured"


def test_required_env_rejects_missing_value(monkeypatch):
    monkeypatch.delenv("MORPHEUS_TEST_VALUE", raising=False)
    with pytest.raises(RuntimeError, match="MORPHEUS_TEST_VALUE"):
        required_env("MORPHEUS_TEST_VALUE")


def test_required_env_rejects_blank_value(monkeypatch):
    monkeypatch.setenv("MORPHEUS_TEST_VALUE", "   ")
    with pytest.raises(RuntimeError, match="MORPHEUS_TEST_VALUE"):
        required_env("MORPHEUS_TEST_VALUE")


def test_run_sensor_fails_before_start_without_configuration(monkeypatch):
    for name in (
        "MORPHEUS_COLLECTOR_URL",
        "MORPHEUS_SENSOR_ID",
        "MORPHEUS_SENSOR_TOKEN_FILE",
    ):
        monkeypatch.delenv(name, raising=False)

    with pytest.raises(RuntimeError, match="MORPHEUS_COLLECTOR_URL"):
        run_sensor()
