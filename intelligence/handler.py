from dataclasses import asdict
from typing import Set

from core.events.bus import EventBus
from core.events.model import MorpheusEvent
from intelligence.campaign.detector import CampaignDetector
from intelligence.fingerprint.engine import FingerprintEngine
from intelligence.intent.classifier import IntentClassifier
from intelligence.mitre.mapper import MitreMapper
from intelligence.response.engine import AdaptiveResponseEngine
from intelligence.risk.engine import RiskScoringEngine
from intelligence.session.reconstructor import SessionReconstructor


class IntelligenceHandler:
    """Coordinate intelligence analysis for completed Cowrie sessions."""

    def __init__(self, event_bus: EventBus) -> None:
        self.event_bus = event_bus
        self.session_reconstructor = SessionReconstructor()
        self.fingerprint_engine = FingerprintEngine()
        self.intent_classifier = IntentClassifier()
        self.mitre_mapper = MitreMapper()
        self.campaign_detector = CampaignDetector()
        self.risk_engine = RiskScoringEngine()
        self.response_engine = AdaptiveResponseEngine()

        # Prevent cumulative intelligence engines from processing the same
        # completed session more than once during this handler's lifetime.
        self.processed_session_ids: Set[str] = set()

    def handle(self, event: MorpheusEvent) -> None:
        """Reconstruct sessions and analyze each session when it closes."""

        self.session_reconstructor.process(event)

        if event.event_type != "cowrie.session.closed":
            return

        session_id = event.data.get("session")
        if not session_id or session_id in self.processed_session_ids:
            return

        session = self.session_reconstructor.get_session(session_id)
        if session is None:
            return

        # Mark before invoking cumulative engines to avoid double-counting
        # if a duplicate close event arrives.
        self.processed_session_ids.add(session_id)

        fingerprint = self.fingerprint_engine.process(session)
        intents = self.intent_classifier.classify(session=session)
        techniques = self.mitre_mapper.map_commands(session.commands)

        campaign = self.campaign_detector.observe(
            session=session,
            fingerprint=fingerprint,
            intents=intents,
        )

        assessment = self.risk_engine.assess(
            session=session,
            intents=intents,
            fingerprint=fingerprint,
            campaign=campaign,
        )
        assessment.fingerprint_id = fingerprint.fingerprint_id

        actions = self.response_engine.evaluate(assessment)

        analysis = {
            "session": asdict(session),
            "fingerprint": asdict(fingerprint),
            "intents": [asdict(item) for item in intents],
            "mitre_techniques": [asdict(item) for item in techniques],
            "campaign": asdict(campaign) if campaign is not None else None,
            "risk_assessment": asdict(assessment),
            "recommended_actions": [asdict(action) for action in actions],
        }

        self.event_bus.publish(
            MorpheusEvent(
                event_type="morpheus.intelligence.analysis",
                source="morpheus",
                data=analysis,
                timestamp=event.timestamp,
            )
        )
