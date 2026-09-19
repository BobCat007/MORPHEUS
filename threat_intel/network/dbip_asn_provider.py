from pathlib import Path
from typing import Optional

import geoip2.database

from threat_intel.network.model import NetworkIntelligence
from threat_intel.network.provider import NetworkIntelligenceProvider


class DBIPASNProvider(NetworkIntelligenceProvider):
    """Network intelligence provider backed by a DB-IP ASN MMDB database."""

    def __init__(self, database_path: str) -> None:
        self.database_path = Path(database_path)

        if not self.database_path.exists():
            raise FileNotFoundError(
                f"DB-IP ASN database not found: {self.database_path}"
            )

        self.reader = geoip2.database.Reader(
            str(self.database_path)
        )

    def lookup(
        self,
        ip: str,
    ) -> Optional[NetworkIntelligence]:
        """Look up ASN and organization information for an IP address."""

        try:
            response = self.reader.asn(ip)
        except geoip2.errors.AddressNotFoundError:
            return None

        asn = response.autonomous_system_number
        organization = response.autonomous_system_organization

        return NetworkIntelligence(
            ip_address=ip,
            asn=f"AS{asn}" if asn is not None else None,
            organization=organization,
            sources=["db-ip"],
        )

    def close(self) -> None:
        """Close the DB-IP ASN database reader."""

        self.reader.close()
