"""Data model for MORPHEUS security alerts."""

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class SecurityAlert:
    """Represent an actionable alert generated from session intelligence."""

    alert_id: str
    session_id: str
    severity: str
    risk_score: int
    source_ip: Optional[str]
    title: str
    description: str
    created_at: str
    risk_factors: List[Dict[str, Any]] = field(default_factory=list)
    previous_severity: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serializable representation of the alert."""

        return asdict(self)
