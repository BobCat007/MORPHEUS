from ipaddress import ip_address
from typing import List, Optional

from threat_intel.ip.model import IPIntelligence
from threat_intel.ip.provider import IPIntelligenceProvider


class IPIntelligenceResolver:
    """Resolve IP intelligence using registered providers."""

    def __init__(
        self,
        providers: Optional[List[IPIntelligenceProvider]] = None,
    ) -> None:
        self.providers = providers or []

    def resolve(self, ip: str) -> IPIntelligence:
        """Resolve an IP address using the configured providers."""

        self._validate_ip(ip)

        for provider in self.providers:
            intelligence = provider.lookup(ip)

            if intelligence is not None:
                return intelligence

        return IPIntelligence(
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
