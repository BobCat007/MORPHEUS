import copy
import pytest

from deception.personality.cowrie_fs import (
    A_CONTENTS, A_NAME, A_TYPE, T_DIR, T_FILE,
    build_cowrie_tree, verify_cowrie_tree,
)


def _tree():
    def directory(name, children):
        return [name, T_DIR, 0, 0, 4096, 0o40755, 1, children, None, None]
    def file(name, data=b"original"):
        return [name, T_FILE, 0, 0, len(data), 0o100644, 1, data, None, None]
    return directory("/", [
        directory("var", [directory("backups", [])]),
        directory("opt", []),
        directory("home", []),
        directory("srv", []),
        directory("etc", [file("hosts", b"preserve me")]),
    ])


def test_builds_all_assets_without_mutating_base():
    base = _tree()
    before = copy.deepcopy(base)
    result = build_cowrie_tree(base)
    assert base == before
    assert verify_cowrie_tree(result)
    assert result != base


def test_preserves_existing_file_content():
    result = build_cowrie_tree(_tree())
    etc = next(n for n in result[A_CONTENTS] if n[A_NAME] == "etc")
    hosts = next(n for n in etc[A_CONTENTS] if n[A_NAME] == "hosts")
    assert hosts[A_CONTENTS] == b"preserve me"


def test_refuses_to_overwrite_existing_asset_path():
    base = _tree()
    backups = next(n for n in base[A_CONTENTS] if n[A_NAME] == "var")[A_CONTENTS][0]
    backups[A_CONTENTS].append(
        ["customer_db.sql", T_FILE, 0, 0, 4, 0o100644, 1, b"keep", None, None]
    )
    with pytest.raises(ValueError, match="Refusing to overwrite"):
        build_cowrie_tree(base)


def test_verification_fails_when_asset_missing():
    with pytest.raises(ValueError, match="Missing or invalid"):
        verify_cowrie_tree(_tree())
