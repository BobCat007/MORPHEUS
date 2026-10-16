from dataclasses import asdict
from typing import Optional, Set

from core.events.bus import EventBus
from core.events.model import MorpheusEvent
from deception.control.controller import DeceptionController
from intelligence.campaign.detector import CampaignDetector
from intelligence.campaign.persistence import restore_campaign_context
from intelligence.fingerprint.engine import FingerprintEngine
from intelligence.intent.classifier import IntentClassifier
from intelligence.mitre.mapper import MitreMapper
from intelligence.response.engine import AdaptiveResponseEngine
from intelligence.risk.engine import RiskScoringEngine
from intelligence.session.reconstructor import SessionReconstructor


class IntelligenceHandler:
    """Coordinate intelligence analysis and optional adaptive deception."""

    def __init__(
        self,
        event_bus: EventBus,
        deception_controller: Optional[DeceptionController] = None,
        adaptive_deception_enabled: bool = False,
        prior_analysis_events: Optional[list] = None,
    ) -> None:
        if adaptive_deception_enabled and deception_controller is None:
            raise ValueError(
                "Adaptive deception requires an explicit controller."
            )

        self.event_bus = event_bus
        self.deception_controller = deception_controller
        self.adaptive_deception_enabled = adaptive_deception_enabled

        self.session_reconstructor = SessionReconstructor()
        self.fingerprint_engine = FingerprintEngine()
        self.intent_classifier = IntentClassifier()
        self.mitre_mapper = MitreMapper()
        self.campaign_detector = CampaignDetector()
        self.risk_engine = RiskScoringEngine()
        self.response_engine = AdaptiveResponseEngine()

        # Prevent duplicate close events from processing a session twice.
        self.processed_session_ids: Set[str] = set()
        if prior_analysis_events:
            self.processed_session_ids.update(
                restore_campaign_context(
                    self.campaign_detector, prior_analysis_events
                )
            )

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

        # Mark before processing so duplicate close events cannot cause
        # repeated analysis or repeated deception actions.
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

        deception_result = {
            "enabled": self.adaptive_deception_enabled,
            "applied": False,
        }

        if self.adaptive_deception_enabled:
            try:
                plan = self.deception_controller.apply_for_risk(assessment)
                deception_result.update(
                    {
                        "applied": True,
                        "plan": asdict(plan),
                    }
                )
            except Exception as exc:
                # Preserve the intelligence result even if the external
                # deception service cannot be reconfigured.
                deception_result["error"] = type(exc).__name__

        analysis = {
            "session": asdict(session),
            "fingerprint": asdict(fingerprint),
            "intents": [asdict(item) for item in intents],
            "mitre_techniques": [asdict(item) for item in techniques],
            "campaign": asdict(campaign) if campaign is not None else None,
            "risk_assessment": asdict(assessment),
            "recommended_actions": [asdict(action) for action in actions],
            "deception": deception_result,
        }

        self.event_bus.publish(
            MorpheusEvent(
                event_type="morpheus.intelligence.analysis",
                source="morpheus",
                data=analysis,
                timestamp=event.timestamp,
            )
        )
