
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


@dataclass(frozen=True)
class Settings:
    """Application settings loaded from environment variables."""

    app_name: str = "MORPHEUS"
    environment: str = os.getenv("MORPHEUS_ENV", "development")
    debug: bool = os.getenv("MORPHEUS_DEBUG", "false").lower() == "true"
    webhook_url: str = os.getenv("MORPHEUS_WEBHOOK_URL", "").strip()
    webhook_timeout: float = _read_webhook_timeout()


settings = Settings()
