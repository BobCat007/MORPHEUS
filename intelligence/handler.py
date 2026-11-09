"""Coordinate session intelligence, IP enrichment, and adaptive deception."""

import logging
from dataclasses import asdict
from ipaddress import ip_address
from pathlib import Path
from typing import Optional, Set

from core.events.bus import EventBus
from core.events.model import MorpheusEvent
from core.config.settings import settings
from deception.control.controller import DeceptionController
from intelligence.campaign.detector import CampaignDetector
from intelligence.campaign.persistence import restore_campaign_context
from intelligence.fingerprint.engine import FingerprintEngine
from intelligence.intent.classifier import IntentClassifier
from intelligence.mitre.mapper import MitreMapper
from intelligence.response.engine import AdaptiveResponseEngine
from intelligence.risk.engine import RiskScoringEngine
from intelligence.session.reconstructor import SessionReconstructor
from threat_intel.ip.abuseipdb_provider import AbuseIPDBProvider
from threat_intel.ip.dbip_provider import DBIPProvider
from threat_intel.ip.resolver import IPIntelligenceResolver
from threat_intel.network.dbip_asn_provider import DBIPASNProvider
from threat_intel.network.resolver import NetworkIntelligenceResolver
from threat_intel.ioc.extractor import IOCExtractor

logger = logging.getLogger(__name__)


class IntelligenceHandler:
    """Coordinate intelligence analysis and optional adaptive deception."""

    def __init__(
        self,
        event_bus: EventBus,
        deception_controller: Optional[DeceptionController] = None,
        adaptive_deception_enabled: bool = False,
        prior_analysis_events: Optional[list] = None,
        ip_resolver: Optional[IPIntelligenceResolver] = None,
        network_resolver: Optional[NetworkIntelligenceResolver] = None,
        honeypot_id: Optional[str] = None,
    ) -> None:
        if adaptive_deception_enabled and deception_controller is None:
            raise ValueError(
                "Adaptive deception requires an explicit controller."
            )

        self.event_bus = event_bus
        self.honeypot_id = (honeypot_id or settings.honeypot_id).strip() or "default"
        self.deception_controller = deception_controller
        self.adaptive_deception_enabled = adaptive_deception_enabled

        # Optional injected resolvers are useful for tests and custom setups.
        # Default DB-IP resolvers are initialized only when a public IP appears.
        self.ip_resolver = ip_resolver
        self.network_resolver = network_resolver

        self.session_reconstructor = SessionReconstructor()
        self.fingerprint_engine = FingerprintEngine()
        self.intent_classifier = IntentClassifier()
        self.mitre_mapper = MitreMapper()
        self.campaign_detector = CampaignDetector()
        self.risk_engine = RiskScoringEngine()
        self.response_engine = AdaptiveResponseEngine()
        self.ioc_extractor = IOCExtractor()

        # Prevent duplicate close events from processing a session twice.
        self.processed_session_ids: Set[str] = set()
        if prior_analysis_events:
            self.processed_session_ids.update(
                restore_campaign_context(
                    self.campaign_detector,
                    prior_analysis_events,
                )
            )

    def _initialize_default_resolvers(self) -> None:
        """Create DB-IP resolvers using databases inside the project."""

        project_root = Path(__file__).resolve().parents[1]

        city_database = (
            project_root
            / "threat_intel"
            / "ip"
            / "data"
            / "dbip-city-lite-2026-09.mmdb"
        )
        asn_database = (
            project_root
            / "threat_intel"
            / "network"
            / "data"
            / "dbip-asn-lite-2026-09.mmdb"
        )

        if self.ip_resolver is None:
            providers = []

            if city_database.is_file():
                try:
                    providers.append(DBIPProvider(str(city_database)))
                except Exception:
                    logger.exception(
                        "Could not initialize DB-IP city database."
                    )
            else:
                logger.warning(
                    "DB-IP city database not found: %s",
                    city_database,
                )

            if settings.abuseipdb_api_key:
                providers.append(
                    AbuseIPDBProvider(
                        api_key=settings.abuseipdb_api_key,
                        timeout=settings.abuseipdb_timeout,
                        max_age_days=settings.abuseipdb_max_age_days,
                    )
                )

            self.ip_resolver = IPIntelligenceResolver(providers=providers)

        if self.network_resolver is None:
            providers = []

            if asn_database.is_file():
                try:
                    providers.append(DBIPASNProvider(str(asn_database)))
                except Exception:
                    logger.exception(
                        "Could not initialize DB-IP ASN database."
                    )
            else:
                logger.warning(
                    "DB-IP ASN database not found: %s",
                    asn_database,
                )

            self.network_resolver = NetworkIntelligenceResolver(
                providers=providers
            )

    @staticmethod
    def _is_public_ip(value: Optional[str]) -> bool:
        """Return True only for globally routable IP addresses."""

        if not value:
            return False

        try:
            return ip_address(value).is_global
        except ValueError:
            return False

    def _resolve_ip_intelligence(self, source_ip: Optional[str]):
        """Resolve geolocation and ASN independently for a public IP."""

        if not self._is_public_ip(source_ip):
            return None, None

        try:
            self._initialize_default_resolvers()
        except Exception:
            logger.exception(
                "Could not initialize IP intelligence resolvers."
            )
            return None, None

        ip_intelligence = None
        network_intelligence = None

        try:
            ip_intelligence = self.ip_resolver.resolve(source_ip)
        except Exception:
            logger.exception(
                "IP geolocation lookup failed for %s.",
                source_ip,
            )

        try:
            network_intelligence = self.network_resolver.resolve(source_ip)
        except Exception:
            logger.exception(
                "ASN lookup failed for %s.",
                source_ip,
            )

        return ip_intelligence, network_intelligence

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
            honeypot_id=self.honeypot_id,
        )

        ip_intelligence, network_intelligence = (
            self._resolve_ip_intelligence(session.source_ip)
        )

        assessment = self.risk_engine.assess(
            session=session,
            intents=intents,
            fingerprint=fingerprint,
            campaign=campaign,
            network=network_intelligence,
            ip_intelligence=ip_intelligence,
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

        indicators = self.ioc_extractor.extract(session)

        analysis = {
            "honeypot_id": self.honeypot_id,
            "indicators_of_compromise": [
                asdict(indicator) for indicator in indicators
            ],
            "session": asdict(session),
            "fingerprint": asdict(fingerprint),
            "intents": [asdict(item) for item in intents],
            "mitre_techniques": [asdict(item) for item in techniques],
            "campaign": asdict(campaign) if campaign is not None else None,
            "ip_intelligence": (
                asdict(ip_intelligence)
                if ip_intelligence is not None
                else None
            ),
            "network_intelligence": (
                asdict(network_intelligence)
                if network_intelligence is not None
                else None
            ),
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
