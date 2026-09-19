import hashlib
from datetime import datetime
from typing import Dict

from intelligence.fingerprint.model import AttackerFingerprint
from intelligence.session.model import ReconstructedSession


class FingerprintEngine:
    """Generate behavioral fingerprints from reconstructed sessions."""

    def __init__(self) -> None:
        self.fingerprints: Dict[str, AttackerFingerprint] = {}

    def process(
        self,
        session: ReconstructedSession,
    ) -> AttackerFingerprint:
        """Process a reconstructed session and update its fingerprint."""

        fingerprint_id = self._generate_id(session)

        if fingerprint_id not in self.fingerprints:
            self.fingerprints[fingerprint_id] = AttackerFingerprint(
                fingerprint_id=fingerprint_id,
                protocol=session.protocol,
                hassh=session.hassh,
                client_version=session.client_version,
            )

        fingerprint = self.fingerprints[fingerprint_id]

        if session.source_ip:
            fingerprint.add_source_ip(session.source_ip)

        if session.username:
            fingerprint.add_username(session.username)

        for command in session.commands:
            fingerprint.add_command(command)

        self._record_command_intervals(
            fingerprint,
            session,
        )

        if session.authentication_success:
            fingerprint.successful_login_count += 1
        else:
            fingerprint.failed_login_count += 1

        fingerprint.add_session(session.duration_ms or 0)

        return fingerprint

    def _record_command_intervals(
        self,
        fingerprint: AttackerFingerprint,
        session: ReconstructedSession,
    ) -> None:
        """Record intervals between consecutive commands."""

        if len(session.command_events) < 2:
            return

        for previous, current in zip(
            session.command_events,
            session.command_events[1:],
        ):
            previous_time = self._parse_timestamp(
                previous.timestamp
            )
            current_time = self._parse_timestamp(
                current.timestamp
            )

            if previous_time is None or current_time is None:
                continue

            interval_ms = int(
                (current_time - previous_time).total_seconds()
                * 1000
            )

            fingerprint.add_command_interval(interval_ms)

    def _parse_timestamp(
        self,
        timestamp: str,
    ):
        """Parse an ISO-8601 timestamp."""

        try:
            return datetime.fromisoformat(
                timestamp.replace("Z", "+00:00")
            )
        except (TypeError, ValueError):
            return None

    def _generate_id(
        self,
        session: ReconstructedSession,
    ) -> str:
        """Generate a stable fingerprint ID from behavioral attributes."""

        behavior = "|".join(
            [
                session.protocol or "",
                session.hassh or "",
                session.client_version or "",
                ",".join(sorted(session.commands)),
            ]
        )

        return hashlib.sha256(
            behavior.encode("utf-8")
        ).hexdigest()[:16]

    def get_all(
        self,
    ) -> Dict[str, AttackerFingerprint]:
        """Return all observed fingerprints."""

        return self.fingerprints
