from configparser import ConfigParser
from pathlib import Path

from deception.control.adapter import DeceptionAdapter
from deception.control.model import DeceptionPlan


class CowrieAdapter(DeceptionAdapter):
    """Apply MORPHEUS deception plans to a Cowrie configuration."""

    def __init__(self, config_path: str) -> None:
        self.config_path = Path(config_path)

    def apply(
        self,
        plan: DeceptionPlan,
    ) -> None:
        """Apply supported deception settings to Cowrie."""

        config = ConfigParser()

        if self.config_path.exists():
            config.read(self.config_path)

        if not config.has_section("honeypot"):
            config.add_section("honeypot")

        config.set(
            "honeypot",
            "hostname",
            plan.hostname,
        )

        with self.config_path.open(
            "w",
            encoding="utf-8",
        ) as file:
            config.write(file)

    def current_state(self) -> DeceptionPlan:
        """Return the currently configured Cowrie hostname."""

        config = ConfigParser()
        config.read(self.config_path)

        hostname = config.get(
            "honeypot",
            "hostname",
            fallback="unknown",
        )

        return DeceptionPlan(
            personality_name="unknown",
            hostname=hostname,
            operating_system="unknown",
            deception_level=0,
        )
