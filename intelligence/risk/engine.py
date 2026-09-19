from typing import List, Optional

from intelligence.campaign.model import AttackCampaign
from intelligence.fingerprint.model import AttackerFingerprint
from intelligence.intent.model import IntentResult
from intelligence.risk.model import RiskAssessment, RiskFactor
from intelligence.session.model import ReconstructedSession
from threat_intel.network.model import NetworkIntelligence


class RiskScoringEngine:
    """Calculate explainable attacker risk assessments."""

    def assess(
        self,
        session: ReconstructedSession,
        intents: Optional[List[IntentResult]] = None,
        fingerprint: Optional[AttackerFingerprint] = None,
        campaign: Optional[AttackCampaign] = None,
        network: Optional[NetworkIntelligence] = None,
    ) -> RiskAssessment:
        """Build a risk assessment from available attacker intelligence."""

        assessment = RiskAssessment(
            session_id=session.session_id,
            source_ip=session.source_ip,
        )

        self._score_authentication(
            assessment,
            session,
        )

        self._score_intents(
            assessment,
            intents,
        )

        self._score_fingerprint(
            assessment,
            fingerprint,
        )

        self._score_campaign(
            assessment,
            campaign,
        )

        self._score_network(
            assessment,
            network,
        )

        assessment.finalize()

        return assessment

    def _score_authentication(
        self,
        assessment: RiskAssessment,
        session: ReconstructedSession,
    ) -> None:
        """Score successful attacker authentication."""

        if not session.authentication_success:
            return

        factor = RiskFactor(
            name="successful_authentication",
            score=10,
            category="authentication",
        )

        if session.username:
            factor.add_evidence(
                f"successful login as {session.username}"
            )

        assessment.add_factor(factor)

    def _score_intents(
        self,
        assessment: RiskAssessment,
        intents: Optional[List[IntentResult]],
    ) -> None:
        """Score observed attacker intents."""

        if not intents:
            return

        intent_scores = {
            "discovery": 10,
            "file_discovery": 10,
            "payload_retrieval": 20,
            "execution": 20,
            "credential_access": 25,
            "defense_evasion": 20,
        }

        for result in intents:
            score = intent_scores.get(
                result.intent,
                5,
            )

            factor = RiskFactor(
                name=f"intent_{result.intent}",
                score=score,
                category="behavior",
                evidence=list(result.evidence),
            )

            assessment.add_factor(factor)

    def _score_fingerprint(
        self,
        assessment: RiskAssessment,
        fingerprint: Optional[AttackerFingerprint],
    ) -> None:
        """Score known behavioral fingerprint information."""

        if fingerprint is None:
            return

        if fingerprint.session_count <= 0:
            return

        factor = RiskFactor(
            name="behavioral_fingerprint",
            score=10,
            category="behavior",
        )

        factor.add_evidence(
            f"fingerprint {fingerprint.fingerprint_id}"
        )

        if fingerprint.session_count > 1:
            factor.add_evidence(
                f"observed across {fingerprint.session_count} sessions"
            )

        assessment.add_factor(factor)

    def _score_campaign(
        self,
        assessment: RiskAssessment,
        campaign: Optional[AttackCampaign],
    ) -> None:
        """Score participation in a correlated attack campaign."""

        if campaign is None:
            return

        if len(campaign.session_ids) < 2:
            return

        factor = RiskFactor(
            name="campaign_correlation",
            score=15,
            category="campaign",
            evidence=list(campaign.correlation_reasons),
        )

        factor.add_evidence(
            f"campaign {campaign.campaign_id}"
        )

        assessment.add_factor(factor)

        assessment.campaign_id = campaign.campaign_id

    def _score_network(
        self,
        assessment: RiskAssessment,
        network: Optional[NetworkIntelligence],
    ) -> None:
        """Attach network intelligence without assuming reputation."""

        if network is None:
            return

        if network.asn:
            factor = RiskFactor(
                name="network_attribution",
                score=5,
                category="network",
            )

            factor.add_evidence(
                network.asn
            )

            if network.organization:
                factor.add_evidence(
                    network.organization
                )

            assessment.add_factor(factor)
