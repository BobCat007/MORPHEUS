from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class ResponseAction:
    """Represents one defensive action MORPHEUS can perform."""

    name: str
    category: str
    description: str

    priority: int = 0
    enabled: bool = True

    parameters: List[str] = field(default_factory=list)

    def add_parameter(self, parameter: str) -> None:
        """Add a parameter required by this response action."""

        if parameter and parameter not in self.parameters:
            self.parameters.append(parameter)


@dataclass
class ResponsePolicy:
    """Represents an adaptive response policy."""

    name: str
    minimum_severity: str

    actions: List[ResponseAction] = field(default_factory=list)

    description: Optional[str] = None

    enabled: bool = True

    def add_action(self, action: ResponseAction) -> None:
        """Add a response action to the policy."""

        if action not in self.actions:
            self.actions.append(action)

    def action_count(self) -> int:
        """Return the number of configured actions."""

        return len(self.actions)
