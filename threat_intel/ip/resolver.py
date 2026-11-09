import logging
from ipaddress import ip_address
from typing import List, Optional

from threat_intel.ip.model import IPIntelligence
from threat_intel.ip.provider import IPIntelligenceProvider

logger = logging.getLogger(__name__)


class IPIntelligenceResolver:
    """Resolve IP intelligence using registered providers."""

    def __init__(
        self,
        providers: Optional[List[IPIntelligenceProvider]] = None,
    ) -> None:
        self.providers = providers or []

    def resolve(self, ip: str) -> IPIntelligence:
        """Resolve an IP address, falling back safely on provider errors."""

        self._validate_ip(ip)

        combined = None
        merge_fields = (
            "country", "country_code", "city",
            "latitude", "longitude", "asn",
            "organization", "reverse_dns",
            "reputation", "reputation_score",
        )

        for provider in self.providers:
            try:
                intelligence = provider.lookup(ip)
            except Exception:
                logger.warning(
                    "IP intelligence provider failed for %s",
                    ip,
                    exc_info=True,
                )
                continue

            if intelligence is None:
                continue

            if intelligence.ip_address != ip:
                logger.warning(
                    "Ignoring mismatched IP intelligence result for %s",
                    ip,
                )
                continue

            if combined is None:
                combined = IPIntelligence(ip_address=ip)

            for field in merge_fields:
                value = getattr(intelligence, field, None)
                if value is not None:
                    setattr(combined, field, value)

            for source in intelligence.sources:
                combined.add_source(source)

        if combined is not None:
            return combined

        return IPIntelligence(
            ip_address=ip,
            sources=["local"],
        )

    def _validate_ip(self, ip: str) -> None:
        try:
            ip_address(ip)
        except ValueError as exc:
            raise ValueError(f"Invalid IP address: {ip}") from exc
