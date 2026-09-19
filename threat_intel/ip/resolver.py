from ipaddress import ip_address
from typing import Optional

from threat_intel.ip.model import IPIntelligence


class IPIntelligenceResolver:
    """Resolve IP intelligence using registered intelligence providers."""

    def resolve(self, ip: str) -> IPIntelligence:
        """Resolve an IP address into normalized intelligence."""

        self._validate_ip(ip)

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
