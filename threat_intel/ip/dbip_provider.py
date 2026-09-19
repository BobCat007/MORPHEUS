from pathlib import Path
from typing import Optional

import geoip2.database

from threat_intel.ip.model import IPIntelligence
from threat_intel.ip.provider import IPIntelligenceProvider


class DBIPProvider(IPIntelligenceProvider):
    """IP intelligence provider backed by a DB-IP MMDB database."""

    def __init__(self, database_path: str) -> None:
        self.database_path = Path(database_path)

        if not self.database_path.exists():
            raise FileNotFoundError(
                f"DB-IP database not found: {self.database_path}"
            )

        self.reader = geoip2.database.Reader(
            str(self.database_path)
        )

    def lookup(
        self,
        ip: str,
    ) -> Optional[IPIntelligence]:
        """Look up geolocation information for an IP address."""

        try:
            response = self.reader.city(ip)
        except geoip2.errors.AddressNotFoundError:
            return None

        return IPIntelligence(
            ip_address=ip,
            country=response.country.name,
            country_code=response.country.iso_code,
            city=response.city.name,
            latitude=response.location.latitude,
            longitude=response.location.longitude,
            sources=["db-ip"],
        )

    def close(self) -> None:
        """Close the DB-IP database reader."""

        self.reader.close()
