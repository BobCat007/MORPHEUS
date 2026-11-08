"""Safely add synthetic assets and personality users to Cowrie's filesystem."""

import copy
import re
import time

from deception.personality.assets import generate_assets


A_NAME, A_TYPE, A_UID, A_GID, A_SIZE, A_MODE, A_CTIME, A_CONTENTS, A_TARGET, A_REALFILE = range(10)
T_DIR, T_FILE = 1, 2


def _find(tree, path):
    node = tree

    for part in path.strip("/").split("/"):
        if not part:
            continue

        if node[A_TYPE] != T_DIR or not isinstance(node[A_CONTENTS], list):
            return None

        node = next(
            (child for child in node[A_CONTENTS] if child[A_NAME] == part),
            None,
        )

        if node is None:
            return None

    return node


def _new_node(name, kind, contents=None):
    now = int(time.time())

    return [
        name,
        kind,
        0,
        0,
        len(contents) if isinstance(contents, bytes) else 4096,
        0o100644 if kind == T_FILE else 0o40755,
        now,
        contents if kind == T_FILE else [],
        None,
        None,
    ]


def _ensure_directory(tree, path):
    """Create missing directories without replacing existing nodes."""
    node = tree

    for part in path.strip("/").split("/"):
        if not part:
            continue

        if node[A_TYPE] != T_DIR or not isinstance(node[A_CONTENTS], list):
            raise ValueError("Invalid directory parent: {}".format(path))

        child = next(
            (item for item in node[A_CONTENTS] if item[A_NAME] == part),
            None,
        )

        if child is None:
            child = _new_node(part, T_DIR)
            node[A_CONTENTS].append(child)

        elif child[A_TYPE] != T_DIR:
            raise ValueError("Path component is not a directory: {}".format(path))

        node = child

    return node


def _read_virtual_file(tree, path):
    node = _find(tree, path)

    if node is None or node[A_TYPE] != T_FILE:
        raise ValueError("Required Cowrie file is missing: {}".format(path))

    if not isinstance(node[A_CONTENTS], bytes):
        raise ValueError("Invalid Cowrie file contents: {}".format(path))

    return node[A_CONTENTS].decode("ascii")


def _write_virtual_file(tree, path, content):
    node = _find(tree, path)

    if node is None or node[A_TYPE] != T_FILE:
        raise ValueError("Required Cowrie file is missing: {}".format(path))

    node[A_CONTENTS] = content.encode("ascii")
    node[A_SIZE] = len(node[A_CONTENTS])



def _set_virtual_tree_ownership(node, uid, gid):
    """Recursively assign ownership within a user's conventional home."""
    node[A_UID] = uid
    node[A_GID] = gid

    if node[A_TYPE] == T_DIR:
        for child in node[A_CONTENTS]:
            _set_virtual_tree_ownership(child, uid, gid)


def _add_personality_users(tree, users):
    """Add missing users/groups while preserving existing virtual accounts."""
    if not users:
        return

    passwd_text = _read_virtual_file(tree, "/etc/passwd")
    group_text = _read_virtual_file(tree, "/etc/group")

    passwd_lines = passwd_text.splitlines()
    group_lines = group_text.splitlines()

    passwd_entries = {}
    used_uids = set()

    for line in passwd_lines:
        if not line.strip():
            continue

        fields = line.split(":")

        if len(fields) != 7:
            raise ValueError("Malformed simulated /etc/passwd entry")

        name, _, uid, _, _, _, _ = fields

        if name in passwd_entries:
            raise ValueError("Duplicate simulated username: {}".format(name))

        passwd_entries[name] = fields
        used_uids.add(int(uid))

    group_entries = {}
    used_gids = set()

    for line in group_lines:
        if not line.strip():
            continue

        fields = line.split(":")

        if len(fields) != 4:
            raise ValueError("Malformed simulated /etc/group entry")

        name, _, gid, _ = fields

        if name in group_entries:
            raise ValueError("Duplicate simulated group: {}".format(name))

        group_entries[name] = fields
        used_gids.add(int(gid))

    for username in users:
        if (
            not isinstance(username, str)
            or not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", username)
        ):
            raise ValueError(
                "Invalid personality username: {!r}".format(username)
            )

        if username in passwd_entries:
            # Preserve existing account details, UID and GID.
            entry = passwd_entries[username]
            uid = int(entry[2])
            gid = int(entry[3])
            home = entry[5]

            home_node = _ensure_directory(tree, home)

            # Only recursively correct conventional user homes.
            # Never modify system directories such as /var/backups.
            if home == "/home/{}".format(username):
                _set_virtual_tree_ownership(home_node, uid, gid)

            continue

        uid = 1500

        while uid in used_uids:
            uid += 1

        if username in group_entries:
            gid = int(group_entries[username][2])

        else:
            gid = 1500

            while gid in used_gids:
                gid += 1

            group_lines.append("{}:x:{}:".format(username, gid))
            group_entries[username] = [
                username,
                "x",
                str(gid),
                "",
            ]
            used_gids.add(gid)

        passwd_lines.append(
            "{}:x:{}:{}:{}:/home/{}:/bin/bash".format(
                username,
                uid,
                gid,
                username,
                username,
            )
        )

        passwd_entries[username] = [
            username,
            "x",
            str(uid),
            str(gid),
            username,
            "/home/{}".format(username),
            "/bin/bash",
        ]

        used_uids.add(uid)

        home_node = _ensure_directory(
            tree,
            "/home/{}".format(username),
        )

        _set_virtual_tree_ownership(home_node, uid, gid)

    _write_virtual_file(tree, "/etc/passwd", "\n".join(passwd_lines) + "\n")
    _write_virtual_file(tree, "/etc/group", "\n".join(group_lines) + "\n")


def build_cowrie_tree(base_tree, paths=None, users=None):
    """Return a copied tree containing synthetic assets and virtual users."""
    if paths is None:
        paths = [
            "/var/backups/customer_db.sql",
            "/opt/company/config/database.yml",
            "/home/backup/credentials.txt",
            "/srv/share/finance.xlsx",
            "/srv/share/employee_data.csv",
            "/opt/company/secrets.env",
        ]

    tree = copy.deepcopy(base_tree)

    assets = generate_assets(paths)

    for path, content in assets.items():
        parent_path, filename = path.rsplit("/", 1)

        parent = _ensure_directory(tree, parent_path)

        existing = next(
            (
                child
                for child in parent[A_CONTENTS]
                if child[A_NAME] == filename
            ),
            None,
        )

        if existing is not None:
            raise ValueError(
                "Refusing to overwrite existing Cowrie path: {}".format(path)
            )

        # Asset generators may return either text or bytes.
        # Convert text once; preserve bytes without encoding them again.
        if isinstance(content, str):
            content = content.encode("ascii")
        elif not isinstance(content, bytes):
            raise TypeError(
                "Generated asset content must be str or bytes: {}".format(path)
            )

        parent[A_CONTENTS].append(
            _new_node(filename, T_FILE, content)
        )

    _add_personality_users(tree, users)

    return tree


def verify_cowrie_tree(tree, paths=None, users=None):
    """Verify that requested assets and virtual users exist."""
    if paths is None:
        paths = [
            "/var/backups/customer_db.sql",
            "/opt/company/config/database.yml",
            "/home/backup/credentials.txt",
            "/srv/share/finance.xlsx",
            "/srv/share/employee_data.csv",
            "/opt/company/secrets.env",
        ]

    for path in paths:
        node = _find(tree, path)

        if node is None or node[A_TYPE] != T_FILE:
            raise ValueError("Missing or invalid Cowrie asset: {}".format(path))

        if not isinstance(node[A_CONTENTS], bytes):
            raise ValueError("Missing or invalid Cowrie asset: {}".format(path))

    if users:
        passwd = _read_virtual_file(tree, "/etc/passwd")
        entries = {}

        for line in passwd.splitlines():
            if line.strip():
                fields = line.split(":")

                if len(fields) != 7:
                    raise ValueError("Malformed simulated /etc/passwd entry")

                entries[fields[0]] = fields

        for username in users:
            if username not in entries:
                raise ValueError(
                    "Missing or invalid Cowrie user: {}".format(username)
                )

            home = _find(tree, entries[username][5])

            if home is None or home[A_TYPE] != T_DIR:
                raise ValueError(
                    "Missing or invalid home directory for user: {}".format(
                        username
                    )
                )

    return True
