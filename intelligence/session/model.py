from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class ReconstructedSession:
    """Represents a reconstructed attacker session."""

    session_id: str
    source_ip: Optional[str] = None
    protocol: Optional[str] = None
    username: Optional[str] = None
    authentication_success: bool = False

    commands: List[str] = field(default_factory=list)

    start_time: Optional[str] = None
    end_time: Optional[str] = None
    duration_ms: Optional[int] = None

    def add_command(self, command: str) -> None:
        """Add an attacker command to the session."""

        self.commands.append(command)

    def command_count(self) -> int:
        """Return the number of commands executed."""

        return len(self.commands)
