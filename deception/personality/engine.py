from typing import List, Optional

from deception.personality.model import HoneypotPersonality
from intelligence.risk.model import RiskAssessment


class PersonalityEngine:
    """Select an adaptive honeypot personality based on attacker risk."""

    SEVERITY_ORDER = {
        "low": 0,
        "medium": 1,
        "high": 2,
        "critical": 3,
    }

    def __init__(
        self,
        personalities: Optional[
            List[HoneypotPersonality]
        ] = None,
    ) -> None:
        self.personalities = (
            personalities
            if personalities is not None
            else self._build_default_personalities()
        )

    def select(
        self,
        assessment: RiskAssessment,
    ) -> Optional[HoneypotPersonality]:
        """Select the most appropriate personality for a risk assessment."""

        available = [
            personality
            for personality in self.personalities
            if personality.enabled
        ]

        if not available:
            return None

        target_level = self.SEVERITY_ORDER.get(
            assessment.severity.lower(),
            0,
        )

        selected = available[0]

        for personality in available:
            if personality.deception_level <= target_level + 1:
                if personality.deception_level > selected.deception_level:
                    selected = personality

        return selected

    def add_personality(
        self,
        personality: HoneypotPersonality,
    ) -> None:
        """Register a new honeypot personality."""

        self.personalities.append(personality)

    def _build_default_personalities(
        self,
    ) -> List[HoneypotPersonality]:
        """Build MORPHEUS's initial adaptive personalities."""

        normal = HoneypotPersonality(
            name="ubuntu_server",
            hostname="app-prod-01",
            operating_system="Ubuntu 22.04",
            deception_level=1,
            description="Standard Ubuntu application server.",
        )

        normal.add_user("ubuntu")
        normal.add_user("admin")

        normal.add_service("ssh")
        normal.add_service("nginx")

        medium = HoneypotPersonality(
            name="ubuntu_enterprise",
            hostname="app-prod-02",
            operating_system="Ubuntu 22.04",
            deception_level=2,
            description="Ubuntu enterprise application server.",
            response_delay_ms=150,
        )

        medium.add_user("ubuntu")
        medium.add_user("deploy")
        medium.add_user("backup")

        medium.add_service("ssh")
        medium.add_service("nginx")
        medium.add_service("mysql")

        medium.add_fake_asset(
            "/var/backups/application.sql"
        )

        high = HoneypotPersonality(
            name="enterprise_database",
            hostname="db-prod-01",
            operating_system="Ubuntu 22.04",
            deception_level=3,
            description="Enterprise database server with deceptive assets.",
            response_delay_ms=300,
        )

        high.add_user("dbadmin")
        high.add_user("backup")
        high.add_user("deploy")

        high.add_service("ssh")
        high.add_service("mysql")
        high.add_service("redis")

        high.add_fake_asset(
            "/var/backups/customer_db.sql"
        )
        high.add_fake_asset(
            "/opt/company/config/database.yml"
        )
        high.add_fake_asset(
            "/home/backup/credentials.txt"
        )

        critical = HoneypotPersonality(
            name="enterprise_internal",
            hostname="internal-jump-01",
            operating_system="Ubuntu 22.04",
            deception_level=4,
            description="Deep enterprise deception environment.",
            response_delay_ms=500,
        )

        critical.add_user("administrator")
        critical.add_user("secops")
        critical.add_user("backup")

        critical.add_service("ssh")
        critical.add_service("nginx")
        critical.add_service("mysql")
        critical.add_service("redis")
        critical.add_service("smb")

        critical.add_fake_asset(
            "/srv/share/finance.xlsx"
        )
        critical.add_fake_asset(
            "/srv/share/employee_data.csv"
        )
        critical.add_fake_asset(
            "/opt/company/secrets.env"
        )
        critical.add_fake_asset(
            "/home/administrator/.ssh/known_hosts"
        )

        return [
            normal,
            medium,
            high,
            critical,
        ]
