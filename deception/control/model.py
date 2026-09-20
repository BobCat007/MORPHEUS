from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class DeceptionChange:
    """Represents one requested change to the deception environment."""

    name: str
    category: str
    value: str

    reason: Optional[str] = None


@dataclass
class DeceptionPlan:
    """Represents the complete deception configuration to apply."""

    personality_name: str

    hostname: str
    operating_system: str

    deception_level: int

    users: List[str] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    fake_assets: List[str] = field(default_factory=list)

    response_delay_ms: int = 0

    changes: List[DeceptionChange] = field(
        default_factory=list
    )

    def add_change(
        self,
        change: DeceptionChange,
    ) -> None:
        """Record a change that should be applied."""

        self.changes.append(change)

    def change_count(self) -> int:
        """Return the number of planned deception changes."""

        return len(self.changes)
