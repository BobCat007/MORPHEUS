from typing import List

from intelligence.response.model import ResponseAction, ResponsePolicy
from intelligence.risk.model import RiskAssessment


class AdaptiveResponseEngine:
    """Select defensive response actions based on attacker risk."""

    SEVERITY_ORDER = {
        "low": 0,
        "medium": 1,
        "high": 2,
        "critical": 3,
    }

    def __init__(self) -> None:
        self.policies = self._build_default_policies()

    def evaluate(
        self,
        assessment: RiskAssessment,
    ) -> List[ResponseAction]:
        """Return response actions appropriate for a risk assessment."""

        actions: List[ResponseAction] = []

        for policy in self.policies:
            if not policy.enabled:
                continue

            if not self._severity_matches(
                assessment.severity,
                policy.minimum_severity,
            ):
                continue

            for action in policy.actions:
                if action.enabled:
                    actions.append(action)

        return self._deduplicate_actions(actions)

    def add_policy(
        self,
        policy: ResponsePolicy,
    ) -> None:
        """Register an additional response policy."""

        self.policies.append(policy)

    def _severity_matches(
        self,
        current_severity: str,
        minimum_severity: str,
    ) -> bool:
        """Check whether current severity meets a policy threshold."""

        current_level = self.SEVERITY_ORDER.get(
            current_severity.lower(),
            -1,
        )

        minimum_level = self.SEVERITY_ORDER.get(
            minimum_severity.lower(),
            -1,
        )

        return current_level >= minimum_level

    def _deduplicate_actions(
        self,
        actions: List[ResponseAction],
    ) -> List[ResponseAction]:
        """Remove duplicate actions while preserving priority order."""

        unique = {}

        for action in actions:
            if action.name not in unique:
                unique[action.name] = action

        return sorted(
            unique.values(),
            key=lambda action: action.priority,
            reverse=True,
        )

    def _build_default_policies(
        self,
    ) -> List[ResponsePolicy]:
        """Build MORPHEUS's initial adaptive response policies."""

        low_policy = ResponsePolicy(
            name="low_risk_observation",
            minimum_severity="low",
            description="Maintain normal observation for low-risk activity.",
        )

        low_policy.add_action(
            ResponseAction(
                name="observe",
                category="monitoring",
                description="Continue normal attacker observation.",
                priority=10,
            )
        )

        medium_policy = ResponsePolicy(
            name="medium_risk_deception",
            minimum_severity="medium",
            description="Increase deception and telemetry collection.",
        )

        medium_policy.add_action(
            ResponseAction(
                name="increase_logging",
                category="monitoring",
                description="Increase telemetry collection for the session.",
                priority=30,
            )
        )

        medium_policy.add_action(
            ResponseAction(
                name="increase_deception",
                category="deception",
                description="Increase the deception level presented to the attacker.",
                priority=20,
            )
        )

        high_policy = ResponsePolicy(
            name="high_risk_collection",
            minimum_severity="high",
            description="Increase intelligence collection for high-risk activity.",
        )

        high_policy.add_action(
            ResponseAction(
                name="expose_fake_asset",
                category="deception",
                description="Expose an additional fake enterprise asset.",
                priority=40,
            )
        )

        high_policy.add_action(
            ResponseAction(
                name="capture_payload",
                category="collection",
                description="Enable enhanced payload collection.",
                priority=35,
            )
        )

        critical_policy = ResponsePolicy(
            name="critical_risk_alert",
            minimum_severity="critical",
            description="Escalate critical attacker activity.",
        )

        critical_policy.add_action(
            ResponseAction(
                name="trigger_alert",
                category="alerting",
                description="Trigger a high-priority security alert.",
                priority=50,
            )
        )

        critical_policy.add_action(
            ResponseAction(
                name="incident_capture",
                category="incident_response",
                description="Preserve enhanced incident evidence.",
                priority=45,
            )
        )

        return [
            low_policy,
            medium_policy,
            high_policy,
            critical_policy,
        ]
