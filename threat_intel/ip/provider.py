from abc import ABC, abstractmethod
from typing import Optional

from threat_intel.ip.model import IPIntelligence


class IPIntelligenceProvider(ABC):
    """Interface for external IP intelligence providers."""

    @abstractmethod
    def lookup(self, ip: str) -> Optional[IPIntelligence]:
        """Return intelligence for an IP address."""

        raise NotImplementedError
