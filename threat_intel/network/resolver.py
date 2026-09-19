from ipaddress import ip_address
from typing import List, Optional

from threat_intel.network.model import NetworkIntelligence
from threat_intel.network.provider import NetworkIntelligenceProvider


class NetworkIntelligenceResolver:
    """Resolve network intelligence using registered providers."""

    def __init__(
        self,
        providers: Optional[
            List[NetworkIntelligenceProvider]
        ] = None,
    ) -> None:
        self.providers = providers or []

    def resolve(
        self,
        ip: str,
    ) -> NetworkIntelligence:
        """Resolve network intelligence for an IP address."""

        self._validate_ip(ip)

        for provider in self.providers:
            intelligence = provider.lookup(ip)

            if intelligence is not None:
                return intelligence

        return NetworkIntelligence(
            ip_address=ip,
            sources=["local"],
        )

    def _validate_ip(self, ip: str) -> None:
        """Validate that the supplied value is a valid IP address."""

        try:
            ip_address(ip)
        except ValueError as exc:
            raise ValueError(
                f"Invalid IP address: {ip}"
            ) from exc
