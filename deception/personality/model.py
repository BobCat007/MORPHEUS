from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class HoneypotPersonality:
    """Represents the identity and deception profile of a honeypot."""

    name: str

    hostname: str
    operating_system: str

    deception_level: int = 1

    users: List[str] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    fake_assets: List[str] = field(default_factory=list)

    response_delay_ms: int = 0

    description: Optional[str] = None
    enabled: bool = True

    def add_user(self, username: str) -> None:
        """Add a visible honeypot user."""

        if username and username not in self.users:
            self.users.append(username)

    def add_service(self, service: str) -> None:
        """Add a visible honeypot service."""

        if service and service not in self.services:
            self.services.append(service)

    def add_fake_asset(self, asset: str) -> None:
        """Add a fake enterprise asset."""

        if asset and asset not in self.fake_assets:
            self.fake_assets.append(asset)

    def asset_count(self) -> int:
        """Return the number of configured fake assets."""

        return len(self.fake_assets)

    def service_count(self) -> int:
        """Return the number of visible services."""

        return len(self.services)

    def user_count(self) -> int:
        """Return the number of visible users."""

        return len(self.users)
