from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class TimelineEvent:
    """Represents one event in an attack timeline."""

    timestamp: str
    event_type: str

    session_id: Optional[str] = None
    command: Optional[str] = None

    technique_id: Optional[str] = None
    technique_name: Optional[str] = None
    tactic: Optional[str] = None

    evidence: List[str] = field(default_factory=list)

    def add_evidence(self, evidence: str) -> None:
        """Add evidence to the timeline event."""

        if evidence not in self.evidence:
            self.evidence.append(evidence)
