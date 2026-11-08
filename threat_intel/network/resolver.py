import logging
from ipaddress import ip_address
from typing import List, Optional

from threat_intel.network.model import NetworkIntelligence
from threat_intel.network.provider import NetworkIntelligenceProvider

logger = logging.getLogger(__name__)


class NetworkIntelligenceResolver:
    """Resolve network intelligence using registered providers."""

    def __init__(
        self,
        providers: Optional[List[NetworkIntelligenceProvider]] = None,
    ) -> None:
        self.providers = providers or []

    def resolve(self, ip: str) -> NetworkIntelligence:
        """Resolve network intelligence with safe provider fallback."""

        self._validate_ip(ip)

        for provider in self.providers:
            try:
                intelligence = provider.lookup(ip)
            except Exception:
                logger.exception(
                    "Network intelligence provider failed for %s",
                    ip,
                )
                continue

            if intelligence is not None:
                return intelligence

        return NetworkIntelligence(
            ip_address=ip,
            sources=["local"],
        )

    def _validate_ip(self, ip: str) -> None:
        try:
            ip_address(ip)
        except ValueError as exc:
            raise ValueError(f"Invalid IP address: {ip}") from exc
