from typing import Optional

from threat_intel.network.model import NetworkIntelligence
from threat_intel.network.provider import NetworkIntelligenceProvider
from threat_intel.network.resolver import NetworkIntelligenceResolver


class MockNetworkProvider(NetworkIntelligenceProvider):
    """Test provider used to verify network intelligence integration."""

    def lookup(
        self,
        ip: str,
    ) -> Optional[NetworkIntelligence]:
        if ip != "8.8.8.8":
            return None

        return NetworkIntelligence(
            ip_address=ip,
            asn="AS15169",
            organization="Google LLC",
            network="8.8.8.0/24",
            isp="Google",
            domain="google.com",
            sources=["mock-provider"],
        )


def test_resolve_valid_ipv4():
    resolver = NetworkIntelligenceResolver()

    intelligence = resolver.resolve(
        "192.168.1.10"
    )

    assert intelligence.ip_address == "192.168.1.10"
    assert intelligence.sources == ["local"]


def test_resolve_valid_ipv6():
    resolver = NetworkIntelligenceResolver()

    intelligence = resolver.resolve(
        "2001:db8::1"
    )

    assert intelligence.ip_address == "2001:db8::1"
    assert intelligence.sources == ["local"]


def test_invalid_ip_raises_error():
    resolver = NetworkIntelligenceResolver()

    try:
        resolver.resolve("999.999.999.999")
        assert False
    except ValueError as exc:
        assert "Invalid IP address" in str(exc)


def test_provider_can_supply_network_intelligence():
    provider = MockNetworkProvider()

    resolver = NetworkIntelligenceResolver(
        providers=[provider]
    )

    intelligence = resolver.resolve(
        "8.8.8.8"
    )

    assert intelligence.ip_address == "8.8.8.8"
    assert intelligence.asn == "AS15169"
    assert intelligence.organization == "Google LLC"
    assert intelligence.network == "8.8.8.0/24"
    assert intelligence.isp == "Google"
    assert intelligence.domain == "google.com"
    assert intelligence.sources == ["mock-provider"]


def test_provider_fallback_when_no_data():
    provider = MockNetworkProvider()

    resolver = NetworkIntelligenceResolver(
        providers=[provider]
    )

    intelligence = resolver.resolve(
        "1.1.1.1"
    )

    assert intelligence.ip_address == "1.1.1.1"
    assert intelligence.sources == ["local"]
    assert intelligence.asn is None


def test_provider_is_not_called_for_invalid_ip():
    provider = MockNetworkProvider()

    resolver = NetworkIntelligenceResolver(
        providers=[provider]
    )

    try:
        resolver.resolve("not-an-ip")
        assert False
    except ValueError as exc:
        assert "Invalid IP address" in str(exc)


def test_network_intelligence_source_can_be_added():
    resolver = NetworkIntelligenceResolver()

    intelligence = resolver.resolve(
        "8.8.8.8"
    )

    intelligence.add_source("test-provider")

    assert intelligence.sources == [
        "local",
        "test-provider",
    ]


def test_duplicate_network_sources_are_not_added():
    resolver = NetworkIntelligenceResolver()

    intelligence = resolver.resolve(
        "8.8.8.8"
    )

    intelligence.add_source("test-provider")
    intelligence.add_source("test-provider")

    assert intelligence.sources == [
        "local",
        "test-provider",
    ]
