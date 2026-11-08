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

        for provider in self.providers:
            try:
                intelligence = provider.lookup(ip)
            except Exception:
                logger.exception(
                    "IP intelligence provider failed for %s",
                    ip,
                )
                continue

            if intelligence is not None:
                return intelligence

        return IPIntelligence(
            ip_address=ip,
            sources=["local"],
        )

    def _validate_ip(self, ip: str) -> None:
        try:
            ip_address(ip)
        except ValueError as exc:
            raise ValueError(f"Invalid IP address: {ip}") from exc
