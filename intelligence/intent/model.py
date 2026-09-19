from dataclasses import dataclass, field
from typing import List


@dataclass
class IntentResult:
    """Represents an inferred attacker intent."""

    intent: str
    confidence: float
    evidence: List[str] = field(default_factory=list)

    def add_evidence(self, evidence: str) -> None:
        """Add evidence supporting the inferred intent."""

        if evidence not in self.evidence:
            self.evidence.append(evidence)
