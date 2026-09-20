from typing import Dict, List, Optional

from intelligence.campaign.model import AttackCampaign
from intelligence.fingerprint.model import AttackerFingerprint
from intelligence.intent.model import IntentResult
from intelligence.session.model import ReconstructedSession


class CampaignDetector:
    """Detect and aggregate relationships between attacker sessions."""

    def __init__(self) -> None:
        self.campaigns: Dict[str, AttackCampaign] = {}

        # Previously observed sessions used as correlation candidates.
        self.sessions: Dict[str, ReconstructedSession] = {}

        # Intelligence associated with each observed session.
        self.fingerprints: Dict[str, AttackerFingerprint] = {}
        self.intents: Dict[str, List[IntentResult]] = {}

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

        campaigns = self._find_matching_campaigns(
            session_one,
            session_two,
        )

        if not campaigns:
            campaign = AttackCampaign(
                campaign_id=self._generate_campaign_id(
                    session_one,
                    session_two,
                )
            )

            self.campaigns[campaign.campaign_id] = campaign

        elif len(campaigns) == 1:
            campaign = campaigns[0]

        else:
            campaign = self._merge_campaigns(
                campaigns
            )

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

    def observe(
        self,
        session: ReconstructedSession,
        fingerprint: Optional[AttackerFingerprint] = None,
        intents: Optional[List[IntentResult]] = None,
    ) -> Optional[AttackCampaign]:
        """Observe a new session and automatically correlate it.

        The session is compared against previously observed sessions.
        If correlation evidence is found, the session is attached to
        the corresponding campaign.

        The first observed session is stored but cannot form a campaign
        by itself, so ``None`` is returned.
        """

        previous_sessions = list(self.sessions.values())

        self.sessions[session.session_id] = session

        if fingerprint is not None:
            self.fingerprints[session.session_id] = fingerprint

        if intents is not None:
            self.intents[session.session_id] = intents

        matched_campaign: Optional[AttackCampaign] = None

        for previous_session in previous_sessions:
            previous_fingerprint = self.fingerprints.get(
                previous_session.session_id
            )

            previous_intents = self.intents.get(
                previous_session.session_id
            )

            campaign = self.correlate(
                previous_session,
                session,
                previous_fingerprint,
                fingerprint,
                previous_intents,
                intents,
            )

            if campaign is not None:
                matched_campaign = campaign

        return matched_campaign

    def _find_matching_campaigns(
        self,
        session_one: ReconstructedSession,
        session_two: ReconstructedSession,
    ) -> List[AttackCampaign]:
        """Find every campaign containing either correlated session."""

        matching_campaigns: List[AttackCampaign] = []

        for campaign in self.campaigns.values():
            if (
                session_one.session_id in campaign.session_ids
                or session_two.session_id in campaign.session_ids
            ):
                matching_campaigns.append(campaign)

        return matching_campaigns

    def _merge_campaigns(
        self,
        campaigns: List[AttackCampaign],
    ) -> AttackCampaign:
        """Merge multiple campaigns connected by new correlation evidence."""

        if not campaigns:
            raise ValueError(
                "At least one campaign is required for merging."
            )

        primary = campaigns[0]

        for campaign in campaigns[1:]:
            for session_id in campaign.session_ids:
                primary.add_session(session_id)

            for fingerprint_id in campaign.fingerprint_ids:
                primary.add_fingerprint(fingerprint_id)

            for source_ip in campaign.source_ips:
                primary.add_source_ip(source_ip)

            for hassh in campaign.hasshs:
                primary.add_hassh(hassh)

            for intent in campaign.intents:
                primary.add_intent(intent)

            for phase in campaign.phases:
                primary.add_phase(phase)

            for reason in campaign.correlation_reasons:
                primary.add_correlation_reason(reason)

            del self.campaigns[campaign.campaign_id]

        return primary

    def _correlation_reasons(
        self,
        session_one: ReconstructedSession,
        session_two: ReconstructedSession,
        fingerprint_one: Optional[AttackerFingerprint],
        fingerprint_two: Optional[AttackerFingerprint],
        intents_one: Optional[List[IntentResult]],
        intents_two: Optional[List[IntentResult]],
    ) -> List[str]:
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
        """Return all observed campaigns."""

        return self.campaigns
