from pathlib import Path

import pytest

from threat_intel.ip.dbip_provider import DBIPProvider


DATABASE_PATH = (
    Path(__file__).resolve().parents[1]
    / "threat_intel"
    / "ip"
    / "data"
    / "dbip-city-lite-2026-09.mmdb"
)


@pytest.mark.skipif(
    not DATABASE_PATH.exists(),
    reason="DB-IP database is not installed",
)
def test_real_dbip_lookup():
    provider = DBIPProvider(
        str(DATABASE_PATH)
    )

    intelligence = provider.lookup(
        "8.8.8.8"
    )

    assert intelligence is not None
    assert intelligence.ip_address == "8.8.8.8"
    assert intelligence.country == "United States"
    assert intelligence.country_code == "US"
    assert intelligence.city == "Mountain View"
    assert intelligence.latitude == 37.422
    assert intelligence.longitude == -122.085
    assert intelligence.sources == ["db-ip"]

    provider.close()


@pytest.mark.skipif(
    not DATABASE_PATH.exists(),
    reason="DB-IP database is not installed",
)
def test_unknown_ip_returns_none():
    provider = DBIPProvider(
        str(DATABASE_PATH)
    )

    intelligence = provider.lookup(
        "192.0.2.123"
    )

    assert intelligence is None

    provider.close()


def test_missing_database_raises_file_not_found(
    tmp_path,
):
    missing_database = (
        tmp_path / "missing.mmdb"
    )

    with pytest.raises(FileNotFoundError):
        DBIPProvider(
            str(missing_database)
        )
