"""AbuseIPDB IP reputation provider."""

import logging
import time
from ipaddress import ip_address
from threading import Lock
from typing import Dict, Optional, Tuple

import httpx

from threat_intel.ip.model import IPIntelligence
from threat_intel.ip.provider import IPIntelligenceProvider

logger = logging.getLogger(__name__)


class AbuseIPDBProvider(IPIntelligenceProvider):
    """Fetch and briefly cache public-IP abuse reputation."""

    ENDPOINT = "https://api.abuseipdb.com/api/v2/check"

    def __init__(
        self,
        api_key: str,
        timeout: float = 3.0,
        max_age_days: int = 90,
        cache_ttl_seconds: int = 3600,
    ) -> None:
        self.api_key = api_key.strip()
        self.timeout = timeout if 0.1 <= timeout <= 15.0 else 3.0
        self.max_age_days = max_age_days if 1 <= max_age_days <= 365 else 90
        self.cache_ttl_seconds = max(0, cache_ttl_seconds)
        self._cache: Dict[str, Tuple[float, IPIntelligence]] = {}
        self._lock = Lock()

    def lookup(self, ip: str) -> Optional[IPIntelligence]:
        """Return AbuseIPDB reputation for a globally routable IP."""

        try:
            parsed_ip = ip_address(ip)
        except ValueError:
            return None

        if not parsed_ip.is_global or not self.api_key:
            return None

        now = time.monotonic()
        with self._lock:
            cached = self._cache.get(ip)
            if cached and cached[0] > now:
                return cached[1]

        try:
            response = httpx.get(
                self.ENDPOINT,
                headers={
                    "Key": self.api_key,
                    "Accept": "application/json",
                },
                params={
                    "ipAddress": ip,
                    "maxAgeInDays": self.max_age_days,
                },
                timeout=self.timeout,
            )
            response.raise_for_status()
            payload = response.json()
            data = payload.get("data") if isinstance(payload, dict) else None

            if not isinstance(data, dict):
                return None

            if data.get("isPublic") is False:
                return None

            score = data.get("abuseConfidenceScore")
            if isinstance(score, bool) or not isinstance(score, (int, float)):
                return None
            if not 0 <= score <= 100:
                return None

            if score >= 75:
                label = "high_reported_abuse"
            elif score >= 25:
                label = "elevated_reported_abuse"
            else:
                label = "low_reported_abuse"

            result = IPIntelligence(
                ip_address=ip,
                reputation=label,
                reputation_score=float(score),
                sources=["abuseipdb"],
            )

            if self.cache_ttl_seconds:
                with self._lock:
                    self._cache[ip] = (
                        time.monotonic() + self.cache_ttl_seconds,
                        result,
                    )

            return result

        except (httpx.HTTPError, ValueError, TypeError, AttributeError):
            logger.warning(
                "AbuseIPDB lookup failed for %s",
                ip,
                exc_info=True,
            )
            return None
