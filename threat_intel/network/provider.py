from abc import ABC, abstractmethod
from typing import Optional

from threat_intel.network.model import NetworkIntelligence


class NetworkIntelligenceProvider(ABC):
    """Interface for network ownership and ASN providers."""

    @abstractmethod
    def lookup(
        self,
        ip: str,
    ) -> Optional[NetworkIntelligence]:
        """Return network intelligence for an IP address."""

        raise NotImplementedError
