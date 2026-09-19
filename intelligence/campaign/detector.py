from typing import Dict, List, Optional

from intelligence.campaign.model import AttackCampaign
from intelligence.fingerprint.model import AttackerFingerprint
from intelligence.intent.model import IntentResult
from intelligence.session.model import ReconstructedSession


class CampaignDetector:
    """Detect and aggregate relationships between attacker sessions."""

    def __init__(self) -> None:
        self.campaigns: Dict[str, AttackCampaign] = {}

    def correlate(
        self,
        session_one: ReconstructedSession,
        session_two: ReconstructedSession,
        fingerprint_one: Optional[AttackerFingerprint] = None,
        fingerprint_two: Optional[AttackerFingerprint] = None,
        intents_one: Optional[List[IntentResult]] = None,
        intents_two: Optional[List[IntentResult]] = None,
    ) -> Optional[AttackCampaign]:
        """Correlate two sessions and add them to an existing campaign."""

        reasons = self._correlation_reasons(
            session_one,
            session_two,
            fingerprint_one,
            fingerprint_two,
            intents_one,
            intents_two,
        )

        if not reasons:
            return None

        campaign = self._find_existing_campaign(
            session_one,
            session_two,
        )

        if campaign is None:
            campaign = AttackCampaign(
                campaign_id=self._generate_campaign_id(
                    session_one,
                    session_two,
                )
            )

            self.campaigns[campaign.campaign_id] = campaign

        self._populate_campaign(
            campaign,
            session_one,
            session_two,
            fingerprint_one,
            fingerprint_two,
            intents_one,
            intents_two,
            reasons,
        )

        return campaign

    def _find_existing_campaign(
        self,
        session_one: ReconstructedSession,
        session_two: ReconstructedSession,
    ) -> Optional[AttackCampaign]:
        """Find a campaign containing either correlated session."""

        for campaign in self.campaigns.values():
            if (
                session_one.session_id in campaign.session_ids
                or session_two.session_id in campaign.session_ids
            ):
                return campaign

        return None

    def _correlation_reasons(
        self,
        session_one: ReconstructedSession,
        session_two: ReconstructedSession,
        fingerprint_one: Optional[AttackerFingerprint],
        fingerprint_two: Optional[AttackerFingerprint],
        intents_one: Optional[List[IntentResult]],
        intents_two: Optional[List[IntentResult]],
    ) -> List[str]:
        """Return explicit reasons why two sessions are related."""

        reasons: List[str] = []

        if (
            session_one.source_ip
            and session_one.source_ip == session_two.source_ip
        ):
            reasons.append("same_source_ip")

        if (
            session_one.hassh
            and session_one.hassh == session_two.hassh
        ):
            reasons.append("same_hassh")

        if (
            session_one.client_version
            and session_one.client_version == session_two.client_version
        ):
            reasons.append("same_client_version")

        if self._shared_commands(
            session_one,
            session_two,
        ):
            reasons.append("shared_commands")

        if (
            fingerprint_one
            and fingerprint_two
            and fingerprint_one.fingerprint_id
            == fingerprint_two.fingerprint_id
        ):
            reasons.append("same_fingerprint")

        if self._shared_intents(
            intents_one,
            intents_two,
        ):
            reasons.append("shared_intent")

        return reasons

    def _shared_commands(
        self,
        session_one: ReconstructedSession,
        session_two: ReconstructedSession,
    ) -> List[str]:
        """Return commands observed in both sessions."""

        commands_one = set(session_one.commands)
        commands_two = set(session_two.commands)

        return sorted(
            commands_one.intersection(commands_two)
        )

    def _shared_intents(
        self,
        intents_one: Optional[List[IntentResult]],
        intents_two: Optional[List[IntentResult]],
    ) -> List[str]:
        """Return intents observed in both sessions."""

        if not intents_one or not intents_two:
            return []

        names_one = {
            result.intent
            for result in intents_one
        }

        names_two = {
            result.intent
            for result in intents_two
        }

        return sorted(
            names_one.intersection(names_two)
        )

    def _populate_campaign(
        self,
        campaign: AttackCampaign,
        session_one: ReconstructedSession,
        session_two: ReconstructedSession,
        fingerprint_one: Optional[AttackerFingerprint],
        fingerprint_two: Optional[AttackerFingerprint],
        intents_one: Optional[List[IntentResult]],
        intents_two: Optional[List[IntentResult]],
        reasons: List[str],
    ) -> None:
        """Populate a campaign with correlated intelligence."""

        campaign.add_session(
            session_one.session_id
        )

        campaign.add_session(
            session_two.session_id
        )

        for fingerprint in (
            fingerprint_one,
            fingerprint_two,
        ):
            if fingerprint:
                campaign.add_fingerprint(
                    fingerprint.fingerprint_id
                )

        for session in (
            session_one,
            session_two,
        ):
            if session.source_ip:
                campaign.add_source_ip(
                    session.source_ip
                )

            if session.hassh:
                campaign.add_hassh(
                    session.hassh
                )

        for intent_results in (
            intents_one,
            intents_two,
        ):
            if not intent_results:
                continue

            for result in intent_results:
                campaign.add_intent(
                    result.intent
                )

                if result.phase:
                    campaign.add_phase(
                        result.phase
                    )

        for reason in reasons:
            campaign.add_correlation_reason(
                reason
            )

    def _generate_campaign_id(
        self,
        session_one: ReconstructedSession,
        session_two: ReconstructedSession,
    ) -> str:
        """Generate a deterministic campaign ID."""

        session_ids = "|".join(
            sorted(
                [
                    session_one.session_id,
                    session_two.session_id,
                ]
            )
        )

        import hashlib

        return hashlib.sha256(
            session_ids.encode("utf-8")
        ).hexdigest()[:16]

    def get_all(self) -> Dict[str, AttackCampaign]:
        """Return all detected campaigns."""

        return self.campaigns
