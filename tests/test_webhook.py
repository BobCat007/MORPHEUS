
"""Tests for MORPHEUS webhook delivery."""

import json
from threading import Event
from urllib.error import URLError

import pytest

from alerts import webhook as webhook_module
from alerts.webhook import WebhookHandler
from core.events.model import MorpheusEvent
import telemetry.cowrie.live_pipeline as live_pipeline


ALERT_TYPE = "morpheus.alert.created"


def _alert_event():
    return MorpheusEvent(
        event_type=ALERT_TYPE,
        source="morpheus.alerting",
        timestamp="2026-10-16T10:00:00+00:00",
        data={
            "alert_id": "MORPHEUS-ALERT-test123",
            "session_id": "webhook-test-session",
            "severity": "critical",
            "risk_score": 95,
            "source_ip": "192.0.2.20",
        },
    )


class FakeResponse:
    def __init__(self, status=200):
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False


def test_successful_delivery_sends_json(monkeypatch):
    captured = {}

    def fake_urlopen(request, timeout):
        captured["request"] = request
        captured["timeout"] = timeout
        return FakeResponse(202)

    monkeypatch.setattr(webhook_module, "urlopen", fake_urlopen)

    handler = WebhookHandler("https://example.test/webhook", timeout=3)
    handler.handle(_alert_event())

    request = captured["request"]
    payload = json.loads(request.data.decode("utf-8"))

    assert request.full_url == "https://example.test/webhook"
    assert request.get_method() == "POST"
    assert request.get_header("Content-type") == "application/json"
    assert captured["timeout"] == 3.0
    assert payload["event_type"] == ALERT_TYPE
    assert payload["data"]["session_id"] == "webhook-test-session"
    assert payload["data"]["severity"] == "critical"


def test_empty_url_disables_delivery(monkeypatch):
    def unexpected_request(*args, **kwargs):
        raise AssertionError("Disabled webhook must not make requests.")

    monkeypatch.setattr(webhook_module, "urlopen", unexpected_request)

    handler = WebhookHandler("")
    assert handler.enabled is False
    handler.handle(_alert_event())


def test_non_alert_events_are_ignored(monkeypatch):
    def unexpected_request(*args, **kwargs):
        raise AssertionError("Non-alert events must not be delivered.")

    monkeypatch.setattr(webhook_module, "urlopen", unexpected_request)

    handler = WebhookHandler("https://example.test/webhook")
    event = MorpheusEvent(
        event_type="morpheus.intelligence.analysis",
        source="morpheus",
        timestamp="2026-10-16T10:00:00+00:00",
        data={},
    )

    handler.handle(event)


def test_network_failure_does_not_raise(monkeypatch):
    def failed_request(*args, **kwargs):
        raise URLError("synthetic connection failure")

    monkeypatch.setattr(webhook_module, "urlopen", failed_request)

    handler = WebhookHandler("https://example.test/webhook")
    handler.handle(_alert_event())


def test_http_error_does_not_raise(monkeypatch):
    from urllib.error import HTTPError

    def failed_request(*args, **kwargs):
        raise HTTPError(
            "https://example.test/webhook",
            503,
            "Service unavailable",
            hdrs=None,
            fp=None,
        )

    monkeypatch.setattr(webhook_module, "urlopen", failed_request)

    handler = WebhookHandler("https://example.test/webhook")
    handler.handle(_alert_event())


@pytest.mark.parametrize(
    "url",
    [
        "ftp://example.test/webhook",
        "not-a-url",
        "https://user:password@example.test/webhook",
    ],
)
def test_invalid_webhook_urls_are_rejected(url):
    with pytest.raises(ValueError):
        WebhookHandler(url)


@pytest.mark.parametrize("timeout", [0, -1, 31, float("nan"), True])
def test_invalid_timeouts_are_rejected(timeout):
    with pytest.raises(ValueError):
        WebhookHandler("https://example.test/webhook", timeout=timeout)


def test_live_pipeline_delivers_created_alert(tmp_path, monkeypatch):
    log_path = tmp_path / "cowrie.json"
    storage_path = tmp_path / "events.jsonl"
    log_path.write_text("", encoding="utf-8")

    captured = {}

    def fake_urlopen(request, timeout):
        captured["payload"] = json.loads(request.data.decode("utf-8"))
        captured["timeout"] = timeout
        return FakeResponse(200)

    monkeypatch.setattr(webhook_module, "urlopen", fake_urlopen)

    class FakeFollower:
        def __init__(
            self,
            log_path,
            event_bus,
            poll_interval,
            start_at_end,
        ):
            self.event_bus = event_bus

        def run(self, stop_event):
            session_id = "live-webhook-session"
            analysis = {
                "session": {
                    "session_id": session_id,
                    "source_ip": "192.0.2.60",
                },
                "risk_assessment": {
                    "session_id": session_id,
                    "source_ip": "192.0.2.60",
                    "severity": "critical",
                    "score": 95,
                    "factors": [],
                },
                "intents": [],
                "mitre_techniques": [],
                "recommended_actions": [],
            }
            self.event_bus.publish(
                MorpheusEvent(
                    event_type="morpheus.intelligence.analysis",
                    source="morpheus.test",
                    data=analysis,
                    timestamp="2026-10-16T10:00:00+00:00",
                )
            )

    monkeypatch.setattr(
        live_pipeline,
        "CowrieLogFollower",
        FakeFollower,
    )

    live_pipeline.run_live_cowrie_pipeline(
        log_path=str(log_path),
        storage_path=str(storage_path),
        stop_event=Event(),
        webhook_url="https://example.test/webhook",
        webhook_timeout=2,
    )

    assert captured["payload"]["event_type"] == ALERT_TYPE
    assert (
        captured["payload"]["data"]["session_id"]
        == "live-webhook-session"
    )
    assert captured["timeout"] == 2.0

    stored = [
        json.loads(line)
        for line in storage_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert any(event["event_type"] == ALERT_TYPE for event in stored)
