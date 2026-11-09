
"""Environment-based configuration for MORPHEUS."""

import os
from dataclasses import dataclass


def _read_webhook_timeout() -> float:
    """Read a bounded webhook timeout, falling back safely."""

    raw_value = os.getenv("MORPHEUS_WEBHOOK_TIMEOUT", "5")

    try:
        timeout = float(raw_value)
    except (TypeError, ValueError):
        return 5.0

    if not 0.1 <= timeout <= 30.0:
        return 5.0

    return timeout


def _read_abuseipdb_timeout() -> float:
    """Read a bounded AbuseIPDB request timeout."""

    try:
        timeout = float(os.getenv("MORPHEUS_ABUSEIPDB_TIMEOUT", "3"))
    except (TypeError, ValueError):
        return 3.0

    return timeout if 0.1 <= timeout <= 15.0 else 3.0


def _read_abuseipdb_max_age_days() -> int:
    """Read the AbuseIPDB reporting lookback period."""

    try:
        days = int(os.getenv("MORPHEUS_ABUSEIPDB_MAX_AGE_DAYS", "90"))
    except (TypeError, ValueError):
        return 90

    return days if 1 <= days <= 365 else 90


@dataclass(frozen=True)
class Settings:
    """Application settings loaded from environment variables."""

    app_name: str = "MORPHEUS"
    environment: str = os.getenv("MORPHEUS_ENV", "development")
    debug: bool = os.getenv("MORPHEUS_DEBUG", "false").lower() == "true"
    webhook_url: str = os.getenv("MORPHEUS_WEBHOOK_URL", "").strip()
    webhook_timeout: float = _read_webhook_timeout()
    honeypot_id: str = os.getenv("MORPHEUS_HONEYPOT_ID", "default").strip() or "default"
    abuseipdb_api_key: str = os.getenv("MORPHEUS_ABUSEIPDB_API_KEY", "").strip()
    abuseipdb_timeout: float = _read_abuseipdb_timeout()
    abuseipdb_max_age_days: int = _read_abuseipdb_max_age_days()


settings = Settings()
