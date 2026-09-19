from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class NetworkIntelligence:
    """Network ownership and ASN intelligence for an IP address."""

    ip_address: str

    asn: Optional[str] = None
    organization: Optional[str] = None
    network: Optional[str] = None

    isp: Optional[str] = None
    domain: Optional[str] = None

    sources: List[str] = field(default_factory=list)

    def add_source(self, source: str) -> None:
        """Record an intelligence source."""

        if source and source not in self.sources:
            self.sources.append(source)
