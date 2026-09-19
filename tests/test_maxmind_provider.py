import pytest

from threat_intel.ip.maxmind_provider import MaxMindProvider


class FakeCountry:
    name = "United States"
    iso_code = "US"


class FakeCity:
    name = "Mountain View"


class FakeLocation:
    latitude = 37.386
    longitude = -122.0838


class FakeResponse:
    country = FakeCountry()
    city = FakeCity()
    location = FakeLocation()


class FakeReader:
    def __init__(self, database_path: str) -> None:
        self.database_path = database_path
        self.closed = False

    def city(self, ip: str) -> FakeResponse:
        if ip == "8.8.8.8":
            return FakeResponse()

        from geoip2.errors import AddressNotFoundError

        raise AddressNotFoundError(
            f"IP not found: {ip}"
        )

    def close(self) -> None:
        self.closed = True


def test_missing_database_raises_file_not_found():
    with pytest.raises(FileNotFoundError):
        MaxMindProvider(
            "threat_intel/ip/data/does-not-exist.mmdb"
        )


def test_lookup_converts_maxmind_response(
    monkeypatch,
    tmp_path,
):
    database_path = tmp_path / "GeoLite2-City.mmdb"
    database_path.touch()

    monkeypatch.setattr(
        "threat_intel.ip.maxmind_provider.geoip2.database.Reader",
        FakeReader,
    )

    provider = MaxMindProvider(
        str(database_path)
    )

    intelligence = provider.lookup("8.8.8.8")

    assert intelligence is not None
    assert intelligence.ip_address == "8.8.8.8"
    assert intelligence.country == "United States"
    assert intelligence.country_code == "US"
    assert intelligence.city == "Mountain View"
    assert intelligence.latitude == 37.386
    assert intelligence.longitude == -122.0838
    assert intelligence.sources == ["maxmind"]

    provider.close()


def test_unknown_ip_returns_none(
    monkeypatch,
    tmp_path,
):
    database_path = tmp_path / "GeoLite2-City.mmdb"
    database_path.touch()

    monkeypatch.setattr(
        "threat_intel.ip.maxmind_provider.geoip2.database.Reader",
        FakeReader,
    )

    provider = MaxMindProvider(
        str(database_path)
    )

    intelligence = provider.lookup(
        "192.0.2.123"
    )

    assert intelligence is None

    provider.close()
