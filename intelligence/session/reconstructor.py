"""Reconstruct validated attacker sessions from Cowrie events."""

import ipaddress
from typing import Dict, Optional

from core.events.model import MorpheusEvent
from intelligence.session.model import ReconstructedSession


class SessionReconstructor:
    """Build attacker sessions while rejecting malformed event fields."""

    def __init__(self) -> None:
        self.sessions: Dict[str, ReconstructedSession] = {}

    @staticmethod
    def _text(value: object) -> Optional[str]:
        """Return a non-empty string, otherwise None."""
        if not isinstance(value, str) or not value.strip():
            return None
        return value

    @classmethod
    def _ip_address(cls, value: object) -> Optional[str]:
        """Return a valid IP address, otherwise None."""
        value = cls._text(value)
        if value is None:
            return None
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            return None

    def process(self, event: MorpheusEvent) -> None:
        """Process an event without allowing malformed fields to corrupt state."""
        data = event.data
        if not isinstance(data, dict):
            return

        session_id = self._text(data.get("session"))
        if session_id is None:
            return

        event_type = event.event_type
        if not isinstance(event_type, str):
            return

        supported_types = {
            "cowrie.session.connect",
            "cowrie.client.version",
            "cowrie.client.kex",
            "cowrie.login.success",
            "cowrie.login.failed",
            "cowrie.command.input",
            "cowrie.session.closed",
        }
        if event_type not in supported_types:
            return

        session = self.sessions.get(session_id)
        if session is None:
            session = ReconstructedSession(session_id=session_id)
            self.sessions[session_id] = session

        timestamp = self._text(event.timestamp)

        if event_type == "cowrie.session.connect":
            source_ip = self._ip_address(data.get("src_ip"))
            protocol = self._text(data.get("protocol"))
            if source_ip is not None:
                session.source_ip = source_ip
            if protocol is not None:
                session.protocol = protocol
            if timestamp is not None:
                session.start_time = timestamp

        elif event_type == "cowrie.client.version":
            value = self._text(data.get("version"))
            if value is not None:
                session.client_version = value

        elif event_type == "cowrie.client.kex":
            value = self._text(data.get("hassh"))
            if value is not None:
                session.hassh = value

        elif event_type in (
            "cowrie.login.success",
            "cowrie.login.failed",
        ):
            username = self._text(data.get("username"))
            if username is not None:
                session.username = username
                session.authentication_success = (
                    event_type == "cowrie.login.success"
                )

        elif event_type == "cowrie.command.input":
            command = self._text(data.get("input"))
            if command is not None:
                session.add_command(command, timestamp)

        elif event_type == "cowrie.session.closed":
            if timestamp is not None:
                session.end_time = timestamp

            duration = data.get("duration_ms")
            if (
                isinstance(duration, int)
                and not isinstance(duration, bool)
                and duration >= 0
            ):
                session.duration_ms = duration

    def get_session(
        self,
        session_id: str,
    ) -> Optional[ReconstructedSession]:
        """Return a reconstructed session by ID."""
        return self.sessions.get(session_id)

    def get_all_sessions(
        self,
    ) -> Dict[str, ReconstructedSession]:
        """Return all reconstructed sessions."""
        return self.sessions
