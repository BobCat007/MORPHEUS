from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class RiskFactor:
    """Represents one factor contributing to an attacker risk assessment."""

    name: str
    score: int
    category: str
    evidence: List[str] = field(default_factory=list)

    def add_evidence(self, evidence: str) -> None:
        """Add supporting evidence to this risk factor."""

        if evidence and evidence not in self.evidence:
            self.evidence.append(evidence)


@dataclass
class RiskAssessment:
    """Represents the overall risk assessment for an attacker session."""

    session_id: str

    score: int = 0
    severity: str = "low"

    factors: List[RiskFactor] = field(default_factory=list)

    source_ip: Optional[str] = None
    fingerprint_id: Optional[str] = None
    campaign_id: Optional[str] = None

    def add_factor(self, factor: RiskFactor) -> None:
        """Add a risk factor to the assessment."""

        self.factors.append(factor)

    def calculate_score(self) -> int:
        """Calculate the total risk score from all factors."""

        self.score = min(
            100,
            max(
                0,
                sum(factor.score for factor in self.factors),
            ),
        )

        return self.score

    def calculate_severity(self) -> str:
        """Convert the risk score into a severity level."""

        if self.score >= 80:
            self.severity = "critical"
        elif self.score >= 60:
            self.severity = "high"
        elif self.score >= 30:
            self.severity = "medium"
        else:
            self.severity = "low"

        return self.severity

    def finalize(self) -> None:
        """Calculate the final score and severity."""

        self.calculate_score()
        self.calculate_severity()

    def factor_count(self) -> int:
        """Return the number of contributing risk factors."""

        return len(self.factors)
