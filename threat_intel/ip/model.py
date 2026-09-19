from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class IPIntelligence:
    """Threat intelligence associated with an IP address."""

    ip_address: str

    country: Optional[str] = None
    country_code: Optional[str] = None
    city: Optional[str] = None

    latitude: Optional[float] = None
    longitude: Optional[float] = None

    asn: Optional[str] = None
    organization: Optional[str] = None

    reverse_dns: Optional[str] = None

    reputation: Optional[str] = None
    reputation_score: Optional[float] = None

    sources: List[str] = field(default_factory=list)

    def add_source(self, source: str) -> None:
        """Record an intelligence source."""

        if source and source not in self.sources:
            self.sources.append(source)
