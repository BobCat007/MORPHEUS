
from typing import List, Optional

from intelligence.campaign.model import AttackCampaign
from intelligence.fingerprint.model import AttackerFingerprint
from intelligence.intent.model import IntentResult
from intelligence.risk.model import RiskAssessment, RiskFactor
from intelligence.session.model import ReconstructedSession
from threat_intel.ip.model import IPIntelligence
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
        ip_intelligence: Optional[IPIntelligence] = None,
    ) -> RiskAssessment:
        """Build a risk assessment from available attacker intelligence."""

        assessment = RiskAssessment(
            session_id=session.session_id,
            source_ip=session.source_ip,
        )

        self._score_authentication(assessment, session)
        self._score_intents(assessment, intents)
        self._score_campaign(assessment, campaign)
        self._score_network(assessment, network)
        self._score_ip_reputation(assessment, ip_intelligence)

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

        sequence_evidence = {
            item
            for result in intents
            if result.intent == "payload_execution_chain"
            for item in result.evidence
        }

        intent_scores = {
            "discovery": 10,
            "file_discovery": 10,
            "sensitive_file_access": 10,
            "payload_retrieval": 20,
            "execution": 20,
            "credential_access": 25,
            "defense_evasion": 20,
            "payload_execution_chain": 30,
        }

        for result in intents:
            evidence = list(result.evidence)

            if result.intent in {"payload_retrieval", "execution"}:
                evidence = [
                    item
                    for item in evidence
                    if item not in sequence_evidence
                ]
                if not evidence:
                    continue

            score = intent_scores.get(result.intent, 5)

            factor = RiskFactor(
                name=f"intent_{result.intent}",
                score=score,
                category="behavior",
                evidence=evidence,
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

        # Weak campaign correlations must not increase attacker risk.
        if campaign.confidence_score < 40:
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

            factor.add_evidence(network.asn)

            if network.organization:
                factor.add_evidence(network.organization)

            assessment.add_factor(factor)


    def _score_ip_reputation(
        self,
        assessment: RiskAssessment,
        intelligence: Optional[IPIntelligence],
    ) -> None:
        """Add a bounded, explainable risk factor from IP reputation."""

        if intelligence is None or intelligence.reputation_score is None:
            return

        score = intelligence.reputation_score
        if not 0 <= score <= 100:
            return

        if score < 25:
            return
        elif score < 50:
            risk_points = 5
        elif score < 75:
            risk_points = 10
        elif score < 90:
            risk_points = 15
        else:
            risk_points = 20

        factor = RiskFactor(
            name="ip_reputation",
            score=risk_points,
            category="threat_intelligence",
        )
        factor.add_evidence(
            f"AbuseIPDB abuse confidence score: {score:g}/100"
        )
        factor.add_evidence(
            f"Reputation classification: {intelligence.reputation or 'unspecified'}"
        )
        assessment.add_factor(factor)
