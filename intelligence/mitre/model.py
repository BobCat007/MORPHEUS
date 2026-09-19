from dataclasses import dataclass, field
from typing import List


@dataclass
class MitreTechnique:
    """Represents a mapped MITRE ATT&CK technique."""

    technique_id: str
    technique_name: str
    tactic: str

    evidence: List[str] = field(default_factory=list)

    def add_evidence(self, evidence: str) -> None:
        """Add supporting evidence if it is not already recorded."""

        if evidence not in self.evidence:
            self.evidence.append(evidence)
