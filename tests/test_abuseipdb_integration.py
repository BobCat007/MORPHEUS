from types import SimpleNamespace

import httpx
import pytest

from intelligence.risk.engine import RiskScoringEngine
from intelligence.session.model import ReconstructedSession
from threat_intel.ip.abuseipdb_provider import AbuseIPDBProvider
from threat_intel.ip.model import IPIntelligence
from threat_intel.ip.resolver import IPIntelligenceResolver


def mock_response(score=80, is_public=True):
    return SimpleNamespace(
        raise_for_status=lambda: None,
        json=lambda: {
            "data": {
                "ipAddress": "8.8.8.8",
                "isPublic": is_public,
                "abuseConfidenceScore": score,
            }
        },
    )


def test_abuseipdb_provider_parses_reputation(monkeypatch):
    calls = []

    def fake_get(url, **kwargs):
        calls.append((url, kwargs))
        return mock_response(85)

    monkeypatch.setattr(httpx, "get", fake_get)

    provider = AbuseIPDBProvider("test-key")
    result = provider.lookup("8.8.8.8")

    assert result is not None
    assert result.ip_address == "8.8.8.8"
    assert result.reputation_score == 85.0
    assert result.reputation == "high_reported_abuse"
    assert result.sources == ["abuseipdb"]

    _, kwargs = calls[0]
    assert kwargs["headers"]["Key"] == "test-key"
    assert kwargs["params"]["ipAddress"] == "8.8.8.8"


def test_abuseipdb_skips_private_ip_without_request(monkeypatch):
    def unexpected_request(*args, **kwargs):
        pytest.fail("Private IP must not trigger an external request")

    monkeypatch.setattr(httpx, "get", unexpected_request)

    provider = AbuseIPDBProvider("test-key")
    assert provider.lookup("192.168.1.10") is None


def test_abuseipdb_skips_lookup_without_api_key(monkeypatch):
    def unexpected_request(*args, **kwargs):
        pytest.fail("Missing API key must not trigger a request")

    monkeypatch.setattr(httpx, "get", unexpected_request)

    provider = AbuseIPDBProvider("")
    assert provider.lookup("8.8.8.8") is None


def test_abuseipdb_caches_successful_result(monkeypatch):
    calls = []

    def fake_get(*args, **kwargs):
        calls.append(1)
        return mock_response(60)

    monkeypatch.setattr(httpx, "get", fake_get)

    provider = AbuseIPDBProvider("test-key")
    first = provider.lookup("8.8.8.8")
    second = provider.lookup("8.8.8.8")

    assert first is not None
    assert second is not None
    assert first.reputation_score == second.reputation_score == 60
    assert len(calls) == 1


def test_abuseipdb_rejects_invalid_score(monkeypatch):
    monkeypatch.setattr(httpx, "get", lambda *a, **k: mock_response(101))

    provider = AbuseIPDBProvider("test-key")
    assert provider.lookup("8.8.8.8") is None


def test_abuseipdb_handles_http_failure(monkeypatch):
    def fail_request(*args, **kwargs):
        raise httpx.HTTPStatusError(
            "rate limited",
            request=httpx.Request("GET", "https://example.test"),
            response=httpx.Response(429),
        )

    monkeypatch.setattr(httpx, "get", fail_request)

    provider = AbuseIPDBProvider("test-key")
    assert provider.lookup("8.8.8.8") is None


def test_resolver_merges_geolocation_and_reputation():
    class GeoProvider:
        def lookup(self, ip):
            return IPIntelligence(
                ip_address=ip,
                country="United States",
                city="Mountain View",
                sources=["db-ip"],
            )

    class ReputationProvider:
        def lookup(self, ip):
            return IPIntelligence(
                ip_address=ip,
                reputation="high_reported_abuse",
                reputation_score=85,
                sources=["abuseipdb"],
            )

    resolver = IPIntelligenceResolver(
        providers=[GeoProvider(), ReputationProvider()]
    )
    result = resolver.resolve("8.8.8.8")

    assert result.country == "United States"
    assert result.city == "Mountain View"
    assert result.reputation_score == 85
    assert result.reputation == "high_reported_abuse"
    assert result.sources == ["db-ip", "abuseipdb"]


@pytest.mark.parametrize(
    ("reputation_score", "expected_risk"),
    [
        (0, 0),
        (24, 0),
        (25, 5),
        (49, 5),
        (50, 10),
        (74, 10),
        (75, 15),
        (89, 15),
        (90, 20),
        (100, 20),
    ],
)
def test_reputation_risk_thresholds(reputation_score, expected_risk):
    intelligence = IPIntelligence(
        ip_address="8.8.8.8",
        reputation="test",
        reputation_score=reputation_score,
        sources=["abuseipdb"],
    )

    assessment = RiskScoringEngine().assess(
        session=ReconstructedSession(session_id="reputation-test"),
        ip_intelligence=intelligence,
    )

    assert assessment.score == expected_risk

    if expected_risk:
        assert assessment.factor_count() == 1
        assert assessment.factors[0].name == "ip_reputation"
        assert assessment.factors[0].category == "threat_intelligence"
    else:
        assert assessment.factor_count() == 0


def test_missing_reputation_does_not_change_risk():
    assessment = RiskScoringEngine().assess(
        session=ReconstructedSession(session_id="no-reputation"),
        ip_intelligence=IPIntelligence(ip_address="8.8.8.8"),
    )

    assert assessment.score == 0
    assert assessment.factor_count() == 0
