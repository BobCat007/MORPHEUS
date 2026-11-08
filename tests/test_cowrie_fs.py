import copy
import pickle
from pathlib import Path

import pytest

from deception.personality.cowrie_fs import (
    A_CONTENTS,
    A_GID,
    A_NAME,
    A_UID,
    T_DIR,
    T_FILE,
    _find,
    build_cowrie_tree,
    verify_cowrie_tree,
)


def _tree():
    def directory(name, children):
        return [
            name, T_DIR, 0, 0, 4096,
            0o40755, 1, children, None, None,
        ]

    def file(name, data=b"original"):
        return [
            name, T_FILE, 0, 0, len(data),
            0o100644, 1, data, None, None,
        ]

    return directory("/", [
        directory("var", [directory("backups", [])]),
        directory("opt", []),
        directory("home", []),
        directory("srv", []),
        directory("etc", [file("hosts", b"preserve me")]),
    ])


def _load_cowrie_baseline():
    baseline_path = (
        Path(__file__).resolve().parents[1]
        / "deployment/cowrie/etc/cowrie-bundled-fs.pickle"
    )

    if not baseline_path.is_file():
        pytest.skip("Cowrie baseline filesystem is unavailable")

    with baseline_path.open("rb") as handle:
        return pickle.load(handle)


def test_builds_all_assets_without_mutating_base():
    base = _tree()
    before = copy.deepcopy(base)

    result = build_cowrie_tree(base)

    assert base == before
    assert verify_cowrie_tree(result)
    assert result != base


def test_preserves_existing_file_content():
    result = build_cowrie_tree(_tree())

    hosts = _find(result, "/etc/hosts")

    assert hosts is not None
    assert hosts[A_CONTENTS] == b"preserve me"


def test_refuses_to_overwrite_existing_asset_path():
    base = _tree()

    backups = _find(base, "/var/backups")
    backups[A_CONTENTS].append([
        "customer_db.sql",
        T_FILE,
        0,
        0,
        4,
        0o100644,
        1,
        b"keep",
        None,
        None,
    ])

    with pytest.raises(ValueError, match="Refusing to overwrite"):
        build_cowrie_tree(base)


def test_verification_fails_when_asset_missing():
    with pytest.raises(ValueError, match="Missing or invalid"):
        verify_cowrie_tree(_tree())


def test_adds_personality_users_without_replacing_existing_accounts():
    baseline = _load_cowrie_baseline()

    users = ["ubuntu", "admin", "backup", "deploy"]

    result = build_cowrie_tree(baseline, [], users)

    assert verify_cowrie_tree(result, [], users)

    passwd_node = _find(result, "/etc/passwd")
    group_node = _find(result, "/etc/group")

    assert passwd_node is not None
    assert group_node is not None

    passwd = passwd_node[A_CONTENTS].decode("ascii")
    group = group_node[A_CONTENTS].decode("ascii")

    entries = {
        line.split(":")[0]: line.split(":")
        for line in passwd.splitlines()
        if line.strip()
    }

    # Existing backup account must retain its original UID and GID.
    assert entries["backup"][2:4] == ["34", "34"]

    for username in users:
        assert username in entries
        assert len(entries[username]) == 7
        assert _find(result, entries[username][5]) is not None

    assert "deploy:x:" in group
    assert "admin:x:" in group


def test_personality_users_receive_unique_ids():
    baseline = _load_cowrie_baseline()

    result = build_cowrie_tree(
        baseline,
        [],
        ["deploy", "dbadmin", "administrator", "secops"],
    )

    passwd_node = _find(result, "/etc/passwd")

    assert passwd_node is not None

    passwd = passwd_node[A_CONTENTS].decode("ascii")

    entries = [
        line.split(":")
        for line in passwd.splitlines()
        if line.strip()
    ]

    uids = [int(entry[2]) for entry in entries]

    assert len(uids) == len(set(uids))


def test_rejects_invalid_personality_username():
    baseline = _load_cowrie_baseline()

    with pytest.raises(
        ValueError,
        match="Invalid personality username",
    ):
        build_cowrie_tree(baseline, [], ["../intruder"])


def test_personality_home_directories_match_user_ownership():
    baseline = _load_cowrie_baseline()

    result = build_cowrie_tree(
        baseline,
        [],
        ["ubuntu", "admin", "backup"],
    )

    for username in ("ubuntu", "admin"):
        passwd_entry = next(
            line.split(":")
            for line in _find(result, "/etc/passwd")[A_CONTENTS]
            .decode("ascii").splitlines()
            if line.startswith(username + ":")
        )

        home = _find(result, passwd_entry[5])

        assert home is not None
        assert home[A_UID] == int(passwd_entry[2])
        assert home[A_GID] == int(passwd_entry[3])

    # Do not change ownership of the existing system backup directory.
    backup_home = _find(result, "/var/backups")

    assert backup_home[A_UID] == 0
    assert backup_home[A_GID] == 0
