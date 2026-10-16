"""Threshold-based security alert generation for MORPHEUS."""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from alerts.model import SecurityAlert


class AlertEngine:
    """Create alerts when analysis reaches a configured severity."""

    SEVERITY_ORDER = {
        "low": 0,
        "medium": 1,
        "high": 2,
        "critical": 3,
    }

    def __init__(self, minimum_severity: str = "high") -> None:
        """Configure the minimum severity required to create an alert."""

        if not isinstance(minimum_severity, str):
            raise ValueError("minimum_severity must be a valid severity.")

        normalized = minimum_severity.strip().lower()
        if normalized not in self.SEVERITY_ORDER:
            raise ValueError(
                "minimum_severity must be low, medium, high, or critical."
            )

        self.minimum_severity = normalized

    def evaluate(
        self,
        analysis: Dict[str, Any],
        created_at: Optional[str] = None,
        previous_severity: Optional[str] = None,
    ) -> Optional[SecurityAlert]:
        """Create an alert if analysis meets the configured threshold."""

        if not isinstance(analysis, dict):
            return None

        risk = analysis.get("risk_assessment")
        session = analysis.get("session")

        if not isinstance(risk, dict) or not isinstance(session, dict):
            return None

        session_id = risk.get("session_id") or session.get("session_id")
        severity = risk.get("severity")

        if not isinstance(session_id, str) or not session_id.strip():
            return None

        if not isinstance(severity, str):
            return None

        severity = severity.strip().lower()
        if severity not in self.SEVERITY_ORDER:
            return None

        if (
            self.SEVERITY_ORDER[severity]
            < self.SEVERITY_ORDER[self.minimum_severity]
        ):
            return None

        score = risk.get("score", 0)
        if isinstance(score, bool) or not isinstance(score, (int, float)):
            score = 0
        score = max(0, min(100, int(score)))

        source_ip = risk.get("source_ip") or session.get("source_ip")
        if not isinstance(source_ip, str):
            source_ip = None

        raw_factors = risk.get("factors", [])
        factors = (
            [factor for factor in raw_factors if isinstance(factor, dict)]
            if isinstance(raw_factors, list)
            else []
        )

        if previous_severity not in self.SEVERITY_ORDER:
            previous_severity = None

        timestamp = created_at or datetime.now(timezone.utc).isoformat()
        alert_id = "MORPHEUS-ALERT-{}".format(uuid.uuid4().hex[:12])

        return SecurityAlert(
            alert_id=alert_id,
            session_id=session_id,
            severity=severity,
            risk_score=score,
            source_ip=source_ip,
            title="{}-risk session detected".format(severity.title()),
            description=(
                "MORPHEUS detected {} risk activity for session {} "
                "with a score of {}/100.".format(
                    severity, session_id, score
                )
            ),
            created_at=timestamp,
            risk_factors=factors,
            previous_severity=previous_severity,
        )
