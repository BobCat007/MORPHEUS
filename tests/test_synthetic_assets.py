import pytest

from deception.personality.assets import MAX_ASSETS, MAX_CONTENT_BYTES, generate_assets


def test_generates_bounded_deterministic_fictional_assets():
    paths = [
        "/var/backups/customer_db.sql",
        "/opt/company/config/database.yml",
        "/home/backup/credentials.txt",
        "/srv/share/finance.xlsx",
        "/srv/share/employee_data.csv",
        "/opt/company/secrets.env",
    ]
    assets = generate_assets(paths)
    assert assets == generate_assets(paths)
    assert set(assets) == set(paths)
    assert all(isinstance(v, bytes) and len(v) <= MAX_CONTENT_BYTES for v in assets.values())
    assert b"example.invalid" in assets[paths[0]]
    assert b"NOT_A_REAL_SECRET" in assets[paths[1]]
    assert b"SYNTHETIC" in assets[paths[2]]
    assert b"Fictional honeypot data only" in assets[paths[3]]
    assert b"example.invalid" in assets[paths[4]]
    assert b"NOT_A_REAL_SECRET" in assets[paths[5]]


@pytest.mark.parametrize("path", [
    "relative/file.txt", "", "/", "/tmp/../etc/passwd", "/etc/./passwd",
    "/etc\\passwd", "/etc/passwd\x00bad", "/" + "a" * 240,
])
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
    paths = ["/tmp/asset-{}.txt".format(i) for i in range(MAX_ASSETS + 1)]
    with pytest.raises(ValueError, match="Too many assets"):
        generate_assets(paths)
