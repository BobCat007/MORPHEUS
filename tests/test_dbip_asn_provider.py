from pathlib import Path

import pytest

from threat_intel.network.dbip_asn_provider import DBIPASNProvider


DATABASE_PATH = (
    Path(__file__).resolve().parents[1]
    / "threat_intel"
    / "network"
    / "data"
    / "dbip-asn-lite-2026-09.mmdb"
)


@pytest.mark.skipif(
    not DATABASE_PATH.exists(),
    reason="DB-IP ASN database is not installed",
)
def test_real_dbip_asn_lookup():
    provider = DBIPASNProvider(str(DATABASE_PATH))

    intelligence = provider.lookup("8.8.8.8")

    assert intelligence is not None
    assert intelligence.ip_address == "8.8.8.8"
    assert intelligence.asn == "AS15169"
    assert intelligence.organization == "Google LLC"
    assert intelligence.network is None
    assert intelligence.isp is None
    assert intelligence.domain is None
    assert intelligence.sources == ["db-ip"]

    provider.close()


@pytest.mark.skipif(
    not DATABASE_PATH.exists(),
    reason="DB-IP ASN database is not installed",
)
def test_unknown_ip_returns_none():
    provider = DBIPASNProvider(str(DATABASE_PATH))

    intelligence = provider.lookup("192.0.2.123")

    assert intelligence is None

    provider.close()


def test_missing_database_raises_file_not_found(tmp_path):
    missing_database = tmp_path / "missing.mmdb"

    with pytest.raises(FileNotFoundError):
        DBIPASNProvider(str(missing_database))
