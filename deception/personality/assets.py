"""Generate bounded, fictional enterprise files for honeypot deception."""

import json
import posixpath
from typing import Dict, List


MAX_ASSETS = 20
MAX_CONTENT_BYTES = 16_384

_TEMPLATES = {
    ".sql": (
        "-- SYNTHETIC MORPHEUS DATA - NOT REAL CUSTOMER INFORMATION\n"
        "CREATE TABLE customers (id INTEGER, name TEXT, email TEXT);\n"
        "INSERT INTO customers VALUES\n"
        "(1001, 'Alex Example', 'alex@example.invalid'),\n"
        "(1002, 'Jordan Sample', 'jordan@example.invalid');\n"
    ),
    ".yml": (
        "# Synthetic configuration for a fictional environment\n"
        "application:\n"
        "  name: example-service\n"
        "  environment: honeypot\n"
        "database:\n"
        "  host: db.internal.example.invalid\n"
        "  username: synthetic_reader\n"
        "  password: NOT_A_REAL_SECRET\n"
    ),
    ".env": (
        "# SYNTHETIC VALUES ONLY - NO REAL SECRETS\n"
        "APP_ENV=honeypot\n"
        "DB_HOST=db.internal.example.invalid\n"
        "DB_USER=synthetic_service\n"
        "DB_PASSWORD=NOT_A_REAL_SECRET\n"
        "API_KEY=FAKE-MORPHEUS-KEY-0000\n"
    ),
    ".csv": (
        "employee_id,name,department,email\n"
        "E1001,Alex Example,Engineering,alex@example.invalid\n"
        "E1002,Jordan Sample,Finance,jordan@example.invalid\n"
        "E1003,Casey Demo,Security,casey@example.invalid\n"
    ),
    ".json": json.dumps(
        {
            "synthetic": True,
            "environment": "morpheus-honeypot",
            "service": "example-service",
            "credentials": {
                "username": "synthetic_user",
                "password": "NOT_A_REAL_SECRET",
            },
        },
        indent=2,
        sort_keys=True,
    ) + "\n",
    ".txt": (
        "MORPHEUS SYNTHETIC ENTERPRISE DOCUMENT\n"
        "This file contains fictional demonstration data only.\n"
        "Environment: honeypot\n"
        "Contact: security@example.invalid\n"
    ),
}


def _validate_path(path: str) -> str:
    """Validate an absolute POSIX virtual path without filesystem access."""
    if not isinstance(path, str) or not path:
        raise ValueError("Asset path must be a non-empty string.")
    if len(path) > 240 or not path.startswith("/"):
        raise ValueError("Asset path must be absolute and at most 240 characters.")
    if "\\" in path or "\x00" in path:
        raise ValueError("Asset path contains an invalid character.")

    normalized = posixpath.normpath(path)
    if normalized != path or normalized == "/" or ".." in path.split("/"):
        raise ValueError("Asset path must be normalized and traversal-free.")

    if any(part.startswith(".") and part in (".", "..") for part in path.split("/")):
        raise ValueError("Asset path contains an unsafe component.")

    return normalized


def _content_for(path: str) -> bytes:
    """Return deterministic, fictional content based on the file extension."""
    extension = posixpath.splitext(path)[1].lower()
    content = _TEMPLATES.get(
        extension,
        "MORPHEUS SYNTHETIC FILE\nFictional honeypot data only.\n",
    )
    encoded = content.encode("utf-8")
    if len(encoded) > MAX_CONTENT_BYTES:
        raise ValueError("Generated asset exceeds the content size limit.")
    return encoded


def generate_assets(paths: List[str]) -> Dict[str, bytes]:
    """Generate synthetic contents for validated virtual paths.

    This function does not read or write files and never accesses host secrets.
    """
    if not isinstance(paths, list):
        raise ValueError("Asset paths must be provided as a list.")
    if len(paths) > MAX_ASSETS:
        raise ValueError("Too many assets requested.")

    result = {}
    for path in paths:
        safe_path = _validate_path(path)
        if safe_path in result:
            raise ValueError("Duplicate asset path: {}".format(safe_path))
        result[safe_path] = _content_for(safe_path)

    return result
