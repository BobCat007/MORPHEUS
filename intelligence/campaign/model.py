from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class AttackCampaign:
    """Represents a group of correlated attacker sessions."""

    campaign_id: str

    session_ids: List[str] = field(default_factory=list)
    fingerprint_ids: List[str] = field(default_factory=list)

    source_ips: List[str] = field(default_factory=list)
    hasshs: List[str] = field(default_factory=list)

    intents: List[str] = field(default_factory=list)
    phases: List[str] = field(default_factory=list)

    correlation_reasons: List[str] = field(default_factory=list)

    first_seen: Optional[str] = None
    last_seen: Optional[str] = None

    def add_session(self, session_id: str) -> None:
        """Add a session to the campaign."""

        if session_id not in self.session_ids:
            self.session_ids.append(session_id)

    def add_fingerprint(self, fingerprint_id: str) -> None:
        """Add a fingerprint associated with the campaign."""

        if fingerprint_id not in self.fingerprint_ids:
            self.fingerprint_ids.append(fingerprint_id)

    def add_source_ip(self, source_ip: str) -> None:
        """Add a source IP associated with the campaign."""

        if source_ip and source_ip not in self.source_ips:
            self.source_ips.append(source_ip)

    def add_hassh(self, hassh: str) -> None:
        """Add an HASSH associated with the campaign."""

        if hassh and hassh not in self.hasshs:
            self.hasshs.append(hassh)

    def add_intent(self, intent: str) -> None:
        """Add an observed attacker intent."""

        if intent and intent not in self.intents:
            self.intents.append(intent)

    def add_phase(self, phase: str) -> None:
        """Add an observed behavioral phase."""

        if phase and phase not in self.phases:
            self.phases.append(phase)

    def add_correlation_reason(self, reason: str) -> None:
        """Record evidence explaining why sessions are correlated."""

        if reason and reason not in self.correlation_reasons:
            self.correlation_reasons.append(reason)

    def update_time_range(
        self,
        start_time: Optional[str],
        end_time: Optional[str],
    ) -> None:
        """Update the temporal boundaries of the campaign."""

        if start_time:
            if (
                self.first_seen is None
                or start_time < self.first_seen
            ):
                self.first_seen = start_time

        if end_time:
            if (
                self.last_seen is None
                or end_time > self.last_seen
            ):
                self.last_seen = end_time
