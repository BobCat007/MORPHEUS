"""Safely add synthetic assets to a copied Cowrie filesystem tree."""
import copy
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
        node = next((child for child in node[A_CONTENTS] if child[A_NAME] == part), None)
        if node is None:
            return None
    return node


def _new_node(name, kind, contents=None):
    now = int(time.time())
    return [
        name, kind, 0, 0,
        len(contents) if isinstance(contents, bytes) else 4096,
        0o100644 if kind == T_FILE else 0o40755,
        now, contents if kind == T_FILE else [], None, None,
    ]


def build_cowrie_tree(base_tree, paths=None):
    """Return a copied tree containing synthetic assets; never mutate base_tree."""
    if paths is None:
        paths = [
            "/var/backups/customer_db.sql",
            "/opt/company/config/database.yml",
            "/home/backup/credentials.txt",
            "/srv/share/finance.xlsx",
            "/srv/share/employee_data.csv",
            "/opt/company/secrets.env",
        ]
    assets = generate_assets(paths)
    tree = copy.deepcopy(base_tree)

    for path, content in assets.items():
        parts = path.strip("/").split("/")
        node = tree
        for part in parts[:-1]:
            if node[A_TYPE] != T_DIR:
                raise ValueError("Parent is not a directory: {}".format(part))
            if not isinstance(node[A_CONTENTS], list):
                raise ValueError("Directory has invalid contents: {}".format(part))
            child = next((c for c in node[A_CONTENTS] if c[A_NAME] == part), None)
            if child is None:
                child = _new_node(part, T_DIR)
                node[A_CONTENTS].append(child)
            elif child[A_TYPE] != T_DIR:
                raise ValueError("Path component is not a directory: {}".format(part))
            node = child

        filename = parts[-1]
        existing = next((c for c in node[A_CONTENTS] if c[A_NAME] == filename), None)
        if existing is not None:
            raise ValueError("Refusing to overwrite existing Cowrie path: {}".format(path))
        node[A_CONTENTS].append(_new_node(filename, T_FILE, content))

    return tree


def verify_cowrie_tree(tree, paths=None):
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
        if node is None or node[A_TYPE] != T_FILE or not isinstance(node[A_CONTENTS], bytes):
            raise ValueError("Missing or invalid synthetic asset: {}".format(path))
    return True
