from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class AttackerFingerprint:
    """Behavioral fingerprint of an observed attacker."""

    fingerprint_id: str

    protocol: Optional[str] = None
    hassh: Optional[str] = None
    client_version: Optional[str] = None

    source_ips: List[str] = field(default_factory=list)
    usernames: List[str] = field(default_factory=list)
    commands: List[str] = field(default_factory=list)

    session_count: int = 0
    command_count: int = 0

    total_duration_ms: int = 0

    failed_login_count: int = 0
    successful_login_count: int = 0

    def add_source_ip(self, source_ip: str) -> None:
        """Record an observed source IP."""

        if source_ip not in self.source_ips:
            self.source_ips.append(source_ip)

    def add_username(self, username: str) -> None:
        """Record a username if it has not been observed before."""

        if username not in self.usernames:
            self.usernames.append(username)

    def add_command(self, command: str) -> None:
        """Record an observed command."""

        self.commands.append(command)
        self.command_count += 1

    def add_session(self, duration_ms: int = 0) -> None:
        """Record a new session."""

        self.session_count += 1
        self.total_duration_ms += duration_ms

    def average_session_duration(self) -> float:
        """Return average session duration in milliseconds."""

        if self.session_count == 0:
            return 0.0

        return self.total_duration_ms / self.session_count
