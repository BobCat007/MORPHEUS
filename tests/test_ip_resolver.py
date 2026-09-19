from threat_intel.ip.resolver import IPIntelligenceResolver


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
