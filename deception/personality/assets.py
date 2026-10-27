"""Generate bounded, fictional Northstar enterprise decoy assets."""

import csv
import io
import json
import posixpath
from typing import Dict, List

from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill
from openpyxl.utils import get_column_letter


MAX_ASSETS = 20
MAX_CONTENT_BYTES = 16_384

COMPANY = "Northstar Financial Systems"
DOMAIN = "northstar.example.invalid"

_EMPLOYEES = [
    ("E1001", "Alex Example", "Engineering", "alex@example.invalid"),
    ("E1002", "Jordan Sample", "Finance", "jordan@example.invalid"),
    ("E1003", "Casey Demo", "Security", "casey@example.invalid"),
    ("E1004", "Taylor Fiction", "Operations", "taylor@example.invalid"),
]

_SQL = """-- SYNTHETIC MORPHEUS DATA - FICTIONAL RECORDS ONLY
-- Company: Northstar Financial Systems
-- Dataset: application customer registry
CREATE TABLE customers (
    customer_id INTEGER PRIMARY KEY,
    customer_name TEXT,
    contact_email TEXT,
    account_tier TEXT,
    status TEXT
);
INSERT INTO customers VALUES
(1001, 'Alex Example', 'alex@example.invalid', 'business', 'active'),
(1002, 'Jordan Sample', 'jordan@example.invalid', 'enterprise', 'active'),
(1003, 'Casey Demo', 'casey@example.invalid', 'standard', 'review');
"""

_DATABASE_YML = """# Northstar Financial Systems
# SYNTHETIC CONFIGURATION - NOT FOR REAL AUTHENTICATION
application:
  name: northstar-customer-portal
  environment: production-simulation
  owner: platform-engineering
database:
  host: db-prod-01.northstar.example.invalid
  port: 3306
  name: northstar_customers
  username: synthetic_app_reader
  password: NOT_A_REAL_SECRET
cache:
  host: cache-prod-01.northstar.example.invalid
  port: 6379
security:
  synthetic_environment: true
"""

_ENV = """# Northstar Financial Systems
# SYNTHETIC VALUES ONLY - NOT VALID CREDENTIALS
APP_NAME=northstar-customer-portal
APP_ENV=production-simulation
APP_REGION=ap-south-simulation
DB_HOST=db-prod-01.northstar.example.invalid
DB_NAME=northstar_customers
DB_USER=synthetic_app
DB_PASSWORD=NOT_A_REAL_SECRET
API_KEY=FAKE-NORTHSTAR-KEY-0000
MORPHEUS_SYNTHETIC=true
"""

_EMPLOYEE_CSV = io.StringIO()
_writer = csv.writer(_EMPLOYEE_CSV, lineterminator="\n")
_writer.writerow(["employee_id", "name", "department", "email"])
_writer.writerows(_EMPLOYEES)
_EMPLOYEE_CSV_TEXT = (
    "# Northstar Financial Systems - SYNTHETIC EMPLOYEE DIRECTORY\n"
    + _EMPLOYEE_CSV.getvalue()
)

_CREDENTIALS = """NORTHSTAR PLATFORM OPERATIONS
================================
Document: Service Account Reference
Classification: INTERNAL - SYNTHETIC HONEYPOT DATA
Owner: Platform Engineering
Last reviewed: 2026-09-15

Service account: synthetic_app_reader
Purpose: Customer portal database access simulation
Database: northstar_customers
Authentication: Disabled outside the simulated environment
Password: NOT_A_REAL_SECRET

Service account: synthetic_backup
Purpose: Backup workflow simulation
Storage: backup-prod-01.northstar.example.invalid
Password: NOT_A_REAL_SECRET

Incident contact: security@example.invalid
Environment marker: MORPHEUS_SYNTHETIC=true
"""

_APPLICATION_LOG = """2026-10-27T09:15:02Z INFO  northstar-customer-portal service starting
2026-10-27T09:15:03Z INFO  environment=production-simulation
2026-10-27T09:15:03Z INFO  config loaded: /opt/northstar/config/application.yml
2026-10-27T09:15:04Z INFO  database target=db-prod-01.northstar.example.invalid:3306
2026-10-27T09:15:04Z INFO  cache target=cache-prod-01.northstar.example.invalid:6379
2026-10-27T09:15:05Z INFO  health check completed status=simulated-ok
# All records are synthetic examples; this is not a live application log.
"""

_DEPLOYMENT_NOTES = """NORTHSTAR FINANCIAL SYSTEMS
Platform Engineering - Deployment Notes
Environment: Synthetic production simulation

Application node: app-prod-01
Secondary application node: app-prod-02
Database node: db-prod-01
Administrative jump node: internal-jump-01

Application: northstar-customer-portal
Configuration: /opt/northstar/config/application.yml
Database schema: northstar_customers
Backup directory: /var/backups/northstar
Operations owner: Platform Engineering
Security contact: security@example.invalid

All hostnames, accounts, and operational records are fictional.
No production credentials or real customer records are present.
"""

_HOSTS_JSON = json.dumps(
    {
        "synthetic": True,
        "organization": COMPANY,
        "domain": DOMAIN,
        "hosts": [
            {
                "hostname": "app-prod-01",
                "role": "customer portal",
                "services": ["ssh", "nginx"],
            },
            {
                "hostname": "app-prod-02",
                "role": "application and deployment",
                "services": ["ssh", "nginx"],
            },
            {
                "hostname": "db-prod-01",
                "role": "customer database simulation",
                "services": ["ssh", "mysql"],
            },
            {
                "hostname": "internal-jump-01",
                "role": "administrative access simulation",
                "services": ["ssh"],
            },
        ],
    },
    indent=2,
    sort_keys=True,
) + "\n"


def _validate_path(path: str) -> str:
    """Validate an absolute POSIX virtual path without filesystem access."""
    if not isinstance(path, str) or not path:
        raise ValueError("Asset path must be a non-empty string.")

    if len(path) > 240 or not path.startswith("/"):
        raise ValueError(
            "Asset path must be absolute and at most 240 characters."
        )

    if "\\" in path or "\x00" in path:
        raise ValueError("Asset path contains an invalid character.")

    normalized = posixpath.normpath(path)

    if normalized != path or normalized == "/" or ".." in path.split("/"):
        raise ValueError("Asset path must be normalized and traversal-free.")

    if any(part in (".", "..") for part in path.split("/")):
        raise ValueError("Asset path contains an unsafe component.")

    return normalized


def _finance_workbook() -> bytes:
    """Build a real XLSX workbook using fictional finance records."""
    workbook = Workbook()
    summary = workbook.active
    summary.title = "Quarterly Summary"

    summary.append([COMPANY])
    summary.append(["Synthetic finance data - not actual financial results"])
    summary.append(["Period", "Department", "Budget (fictional USD)", "Actual (fictional USD)"])

    rows = [
        ("2026-Q3", "Engineering", 180000, 171500),
        ("2026-Q3", "Finance", 95000, 92300),
        ("2026-Q3", "Operations", 120000, 117250),
        ("2026-Q3", "Security", 110000, 106800),
    ]

    for row in rows:
        summary.append(list(row))

    summary.freeze_panes = "A4"
    summary.auto_filter.ref = "A3:D{}".format(summary.max_row)

    for cell in summary[3]:
        cell.font = Font(bold=True, color="FFFFFF")
        cell.fill = PatternFill(
            fill_type="solid",
            fgColor="1F4E78",
        )

    for column in range(1, summary.max_column + 1):
        values = [
            len(str(summary.cell(row=row, column=column).value or ""))
            for row in range(1, summary.max_row + 1)
        ]
        summary.column_dimensions[get_column_letter(column)].width = min(
            max(max(values) + 2, 14),
            48,
        )

    workbook.properties.title = "Northstar Synthetic Quarterly Finance"
    workbook.properties.subject = "Fictional enterprise honeypot dataset"
    workbook.properties.creator = "MORPHEUS"
    workbook.properties.description = (
        "Synthetic records only. No actual financial information."
    )

    output = io.BytesIO()
    workbook.save(output)
    workbook.close()
    return output.getvalue()


def _content_for(path: str) -> bytes:
    """Return deterministic fictional content based on virtual path."""
    normalized = path.lower()
    extension = posixpath.splitext(normalized)[1]

    if normalized.endswith("/finance.xlsx"):
        encoded = _finance_workbook()

    elif normalized.endswith("/employee_data.csv"):
        encoded = _EMPLOYEE_CSV_TEXT.encode("utf-8")

    elif normalized.endswith("/customer_db.sql"):
        encoded = _SQL.encode("utf-8")

    elif normalized.endswith("/application.sql"):
        encoded = _SQL.encode("utf-8")

    elif normalized.endswith("/database.yml"):
        encoded = _DATABASE_YML.encode("utf-8")

    elif normalized.endswith("/secrets.env"):
        encoded = _ENV.encode("utf-8")

    elif normalized.endswith("/credentials.txt"):
        encoded = _CREDENTIALS.encode("utf-8")

    elif normalized.endswith("/known_hosts"):
        encoded = (
            "# SYNTHETIC HOST REFERENCES - NOT TRUSTED KEY MATERIAL\n"
            "app-prod-01.northstar.example.invalid synthetic-key-placeholder\n"
            "db-prod-01.northstar.example.invalid synthetic-key-placeholder\n"
        ).encode("utf-8")

    elif normalized.endswith("/deployment.txt"):
        encoded = _DEPLOYMENT_NOTES.encode("utf-8")

    elif normalized.endswith("/application.log"):
        encoded = _APPLICATION_LOG.encode("utf-8")

    elif normalized.endswith("/hosts.json"):
        encoded = _HOSTS_JSON.encode("utf-8")

    elif extension == ".json":
        encoded = _HOSTS_JSON.encode("utf-8")

    elif extension == ".yml":
        encoded = _DATABASE_YML.encode("utf-8")

    elif extension == ".env":
        encoded = _ENV.encode("utf-8")

    elif extension == ".sql":
        encoded = _SQL.encode("utf-8")

    elif extension == ".csv":
        encoded = _EMPLOYEE_CSV_TEXT.encode("utf-8")

    else:
        encoded = (
            "{}\n"
            "Document type: Synthetic enterprise decoy\n"
            "Organization: {}\n"
            "Environment: MORPHEUS honeypot simulation\n"
            "Contact: security@example.invalid\n"
            "No real personal data or credentials are present.\n"
        ).format(posixpath.basename(path), COMPANY).encode("utf-8")

    if len(encoded) > MAX_CONTENT_BYTES:
        raise ValueError("Generated asset exceeds the content size limit.")

    return encoded


def generate_assets(paths: List[str]) -> Dict[str, bytes]:
    """Generate bounded synthetic contents without accessing host files."""
    if not isinstance(paths, list):
        raise ValueError("Asset paths must be provided as a list.")

    if len(paths) > MAX_ASSETS:
        raise ValueError("Too many assets requested.")

    result: Dict[str, bytes] = {}

    for path in paths:
        safe_path = _validate_path(path)

        if safe_path in result:
            raise ValueError(
                "Duplicate asset path: {}".format(safe_path)
            )

        result[safe_path] = _content_for(safe_path)

    return result
