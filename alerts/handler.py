"""Connect intelligence events to persistent MORPHEUS security alerts."""

from typing import Dict, Optional

from alerts.engine import AlertEngine
from core.events.bus import EventBus
from core.events.model import MorpheusEvent
from core.storage.event_store import EventStore


ANALYSIS_EVENT_TYPE = "morpheus.intelligence.analysis"
ALERT_EVENT_TYPE = "morpheus.alert.created"


class AlertingHandler:
    """Evaluate analysis events and publish deduplicated alert events."""

    def __init__(
        self,
        event_bus: EventBus,
        event_store: EventStore,
        engine: Optional[AlertEngine] = None,
    ) -> None:
        self.event_bus = event_bus
        self.event_store = event_store
        self.engine = engine or AlertEngine()

        self._highest_alerted_severity: Dict[str, str] = {}
        self._load_existing_alerts()

    def _load_existing_alerts(self) -> None:
        """Restore alert deduplication state from persisted events."""

        severity_order = self.engine.SEVERITY_ORDER

        for event in self.event_store.read_all():
            if event.get("event_type") != ALERT_EVENT_TYPE:
                continue

            data = event.get("data")
            if not isinstance(data, dict):
                continue

            session_id = data.get("session_id")
            severity = data.get("severity")

            if (
                not isinstance(session_id, str)
                or severity not in severity_order
            ):
                continue

            previous = self._highest_alerted_severity.get(session_id)
            if (
                previous is None
                or severity_order[severity] > severity_order[previous]
            ):
                self._highest_alerted_severity[session_id] = severity

    def handle(self, event: MorpheusEvent) -> None:
        """Create an alert for qualifying analysis, including escalations."""

        if event.event_type != ANALYSIS_EVENT_TYPE:
            return

        analysis = event.data
        if not isinstance(analysis, dict):
            return

        session = analysis.get("session")
        risk = analysis.get("risk_assessment")

        session_id = None
        if isinstance(risk, dict):
            session_id = risk.get("session_id")
        if not session_id and isinstance(session, dict):
            session_id = session.get("session_id")

        if not isinstance(session_id, str) or not session_id.strip():
            return

        previous = self._highest_alerted_severity.get(session_id)
        alert = self.engine.evaluate(
            analysis=analysis,
            created_at=event.timestamp,
            previous_severity=previous,
        )
        if alert is None:
            return

        severity_order = self.engine.SEVERITY_ORDER
        if previous is not None:
            if severity_order[alert.severity] <= severity_order[previous]:
                return

        alert_event = MorpheusEvent(
            event_type=ALERT_EVENT_TYPE,
            source="morpheus.alerting",
            data=alert.to_dict(),
            timestamp=event.timestamp,
        )

        # The pipeline subscribes the event store to ALERT_EVENT_TYPE.
        self.event_bus.publish(alert_event)

        # Update state only after the alert event was successfully published.
        self._highest_alerted_severity[session_id] = alert.severity
