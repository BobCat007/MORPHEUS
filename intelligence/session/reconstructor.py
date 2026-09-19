from typing import Dict

from core.events.model import MorpheusEvent
from intelligence.session.model import ReconstructedSession


class SessionReconstructor:
    """Build attacker sessions from individual MORPHEUS events."""

    def __init__(self) -> None:
        self.sessions: Dict[str, ReconstructedSession] = {}

    def process(self, event: MorpheusEvent) -> None:
        """Process one event and update its corresponding session."""

        session_id = event.data.get("session")

        if not session_id:
            return

        if session_id not in self.sessions:
            self.sessions[session_id] = ReconstructedSession(
                session_id=session_id
            )

        session = self.sessions[session_id]

        if event.event_type == "cowrie.session.connect":
            session.source_ip = event.data.get("src_ip")
            session.protocol = event.data.get("protocol")
            session.start_time = event.timestamp

        elif event.event_type == "cowrie.login.success":
            session.username = event.data.get("username")
            session.authentication_success = True

        elif event.event_type == "cowrie.command.input":
            command = event.data.get("input")

            if command:
                session.add_command(command)

        elif event.event_type == "cowrie.session.closed":
            session.end_time = event.timestamp
            session.duration_ms = event.data.get("duration_ms")

    def get_session(self, session_id: str):
        """Return a reconstructed session by ID."""

        return self.sessions.get(session_id)

    def get_all_sessions(self) -> Dict[str, ReconstructedSession]:
        """Return all reconstructed sessions."""

        return self.sessions
