import io

import pytest
from openpyxl import load_workbook

from deception.personality.assets import (
    MAX_ASSETS,
    MAX_CONTENT_BYTES,
    generate_assets,
)


ASSET_PATHS = [
    "/var/backups/customer_db.sql",
    "/opt/company/config/database.yml",
    "/home/backup/credentials.txt",
    "/srv/share/finance.xlsx",
    "/srv/share/employee_data.csv",
    "/opt/company/secrets.env",
]


def test_generates_bounded_deterministic_fictional_assets():
    assets = generate_assets(ASSET_PATHS)

    assert assets == generate_assets(ASSET_PATHS)
    assert set(assets) == set(ASSET_PATHS)
    assert all(isinstance(value, bytes) for value in assets.values())
    assert all(len(value) <= MAX_CONTENT_BYTES for value in assets.values())

    assert b"example.invalid" in assets["/var/backups/customer_db.sql"]
    assert b"NOT_A_REAL_SECRET" in assets["/opt/company/config/database.yml"]
    assert b"SYNTHETIC" in assets["/home/backup/credentials.txt"]
    assert b"example.invalid" in assets["/srv/share/employee_data.csv"]
    assert b"NOT_A_REAL_SECRET" in assets["/opt/company/secrets.env"]


def test_finance_asset_is_a_real_xlsx_workbook():
    assets = generate_assets(["/srv/share/finance.xlsx"])
    content = assets["/srv/share/finance.xlsx"]

    assert content[:2] == b"PK"

    workbook = load_workbook(io.BytesIO(content), read_only=True, data_only=True)
    try:
        assert "Quarterly Summary" in workbook.sheetnames

        sheet = workbook["Quarterly Summary"]
        assert sheet["A1"].value == "Northstar Financial Systems"
        assert "Synthetic finance data" in sheet["A2"].value
        assert sheet.max_row >= 7
    finally:
        workbook.close()


@pytest.mark.parametrize(
    "path",
    [
        "relative/file.txt",
        "",
        "/",
        "/tmp/../etc/passwd",
        "/etc/./passwd",
        "/etc\\passwd",
        "/etc/passwd\x00bad",
        "/" + "a" * 240,
    ],
)
def test_rejects_invalid_paths(path):
    with pytest.raises(ValueError):
        generate_assets([path])


def test_rejects_non_list_input():
    with pytest.raises(ValueError):
        generate_assets(("/tmp/example.txt",))


def test_rejects_duplicate_paths():
    with pytest.raises(ValueError, match="Duplicate asset path"):
        generate_assets(["/tmp/example.txt", "/tmp/example.txt"])


def test_rejects_too_many_assets():
    paths = [
        "/tmp/asset-{}.txt".format(index)
        for index in range(MAX_ASSETS + 1)
    ]

    with pytest.raises(ValueError, match="Too many assets"):
        generate_assets(paths)


def test_enterprise_records_use_consistent_fictional_identity():
    assets = generate_assets(
        [
            "/opt/company/config/database.yml",
            "/opt/company/secrets.env",
            "/srv/share/employee_data.csv",
        ]
    )

    assert b"northstar-customer-portal" in assets[
        "/opt/company/config/database.yml"
    ]
    assert b"db-prod-01.northstar.example.invalid" in assets[
        "/opt/company/config/database.yml"
    ]
    assert b"Northstar Financial Systems" in assets[
        "/srv/share/employee_data.csv"
    ]
    assert b"MORPHEUS_SYNTHETIC=true" in assets[
        "/opt/company/secrets.env"
    ]
