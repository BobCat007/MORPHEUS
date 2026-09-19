from pathlib import Path
from typing import Optional

from threat_intel.ip.dbip_provider import DBIPProvider
from threat_intel.ip.model import IPIntelligence
from threat_intel.ip.provider import IPIntelligenceProvider
from threat_intel.ip.resolver import IPIntelligenceResolver


class MockIPProvider(IPIntelligenceProvider):
    """Test provider used to verify provider integration."""

    def lookup(
        self,
        ip: str,
    ) -> Optional[IPIntelligence]:
        if ip != "8.8.8.8":
            return None

        return IPIntelligence(
            ip_address=ip,
            country="United States",
            country_code="US",
            city="Mountain View",
            asn="AS15169",
            organization="Google LLC",
            sources=["mock-provider"],
        )


def test_resolve_valid_ipv4():
    resolver = IPIntelligenceResolver()

    intelligence = resolver.resolve("192.168.1.10")

    assert intelligence.ip_address == "192.168.1.10"
    assert intelligence.sources == ["local"]


def test_resolve_valid_ipv6():
    resolver = IPIntelligenceResolver()

    intelligence = resolver.resolve("2001:db8::1")

    assert intelligence.ip_address == "2001:db8::1"
    assert intelligence.sources == ["local"]


def test_invalid_ip_raises_error():
    resolver = IPIntelligenceResolver()

    try:
        resolver.resolve("999.999.999.999")
        assert False
    except ValueError as exc:
        assert "Invalid IP address" in str(exc)


def test_ip_intelligence_defaults_are_empty():
    resolver = IPIntelligenceResolver()

    intelligence = resolver.resolve("8.8.8.8")

    assert intelligence.country is None
    assert intelligence.city is None
    assert intelligence.asn is None
    assert intelligence.organization is None
    assert intelligence.reputation is None
    assert intelligence.reputation_score is None


def test_ip_intelligence_source_can_be_added():
    resolver = IPIntelligenceResolver()

    intelligence = resolver.resolve("8.8.8.8")

    intelligence.add_source("maxmind")

    assert intelligence.sources == [
        "local",
        "maxmind",
    ]


def test_duplicate_sources_are_not_added():
    resolver = IPIntelligenceResolver()

    intelligence = resolver.resolve("8.8.8.8")

    intelligence.add_source("maxmind")
    intelligence.add_source("maxmind")

    assert intelligence.sources == [
        "local",
        "maxmind",
    ]


def test_provider_can_supply_ip_intelligence():
    provider = MockIPProvider()

    resolver = IPIntelligenceResolver(
        providers=[provider]
    )

    intelligence = resolver.resolve("8.8.8.8")

    assert intelligence.ip_address == "8.8.8.8"
    assert intelligence.country == "United States"
    assert intelligence.country_code == "US"
    assert intelligence.city == "Mountain View"
    assert intelligence.asn == "AS15169"
    assert intelligence.organization == "Google LLC"
    assert intelligence.sources == ["mock-provider"]


def test_provider_fallback_when_provider_has_no_data():
    provider = MockIPProvider()

    resolver = IPIntelligenceResolver(
        providers=[provider]
    )

    intelligence = resolver.resolve("1.1.1.1")

    assert intelligence.ip_address == "1.1.1.1"
    assert intelligence.sources == ["local"]
    assert intelligence.country is None


def test_provider_is_not_called_for_invalid_ip():
    provider = MockIPProvider()

    resolver = IPIntelligenceResolver(
        providers=[provider]
    )

    try:
        resolver.resolve("not-an-ip")
        assert False
    except ValueError as exc:
        assert "Invalid IP address" in str(exc)


def test_real_dbip_provider_works_through_resolver():
    database_path = (
        Path(__file__).resolve().parents[1]
        / "threat_intel"
        / "ip"
        / "data"
        / "dbip-city-lite-2026-09.mmdb"
    )

    if not database_path.exists():
        return

    provider = DBIPProvider(
        str(database_path)
    )

    resolver = IPIntelligenceResolver(
        providers=[provider]
    )

    intelligence = resolver.resolve(
        "8.8.8.8"
    )

    assert intelligence.ip_address == "8.8.8.8"
    assert intelligence.country == "United States"
    assert intelligence.country_code == "US"
    assert intelligence.city == "Mountain View"
    assert intelligence.latitude == 37.422
    assert intelligence.longitude == -122.085
    assert intelligence.sources == ["db-ip"]

    provider.close()
