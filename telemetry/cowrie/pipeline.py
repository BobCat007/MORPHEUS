"""Offline Cowrie ingestion and intelligence pipeline."""

from alerts.engine import AlertEngine
from alerts.handler import ALERT_EVENT_TYPE, AlertingHandler
from core.events.bus import EventBus
from core.storage.event_store import EventStore
from core.storage.handler import EventStorageHandler
from intelligence.handler import IntelligenceHandler
from telemetry.cowrie.ingest import ingest_cowrie_events


ANALYSIS_EVENT_TYPE = "morpheus.intelligence.analysis"


def run_cowrie_pipeline(
    log_path: str,
    storage_path: str,
    alert_minimum_severity: str = "high",
) -> int:
    """Process Cowrie telemetry, analyze sessions, and persist alerts."""

    event_bus = EventBus()
    event_store = EventStore(storage_path)
    storage_handler = EventStorageHandler(event_store)
    intelligence_handler = IntelligenceHandler(event_bus)
    alerting_handler = AlertingHandler(
        event_bus,
        event_store,
        AlertEngine(minimum_severity=alert_minimum_severity),
    )

    event_types = [
        "cowrie.session.connect",
        "cowrie.client.version",
        "cowrie.client.kex",
        "cowrie.login.success",
        "cowrie.login.failed",
        "cowrie.client.size",
        "cowrie.client.var",
        "cowrie.session.params",
        "cowrie.command.input",
        "cowrie.command.failed",
        "cowrie.log.closed",
        "cowrie.session.closed",
    ]

    for event_type in event_types:
        event_bus.subscribe(event_type, storage_handler.handle)
        event_bus.subscribe(event_type, intelligence_handler.handle)

    # Persist analysis events before evaluating them for alerts.
    event_bus.subscribe(ANALYSIS_EVENT_TYPE, storage_handler.handle)
    event_bus.subscribe(ALERT_EVENT_TYPE, storage_handler.handle)
    event_bus.subscribe(ANALYSIS_EVENT_TYPE, alerting_handler.handle)

    return ingest_cowrie_events(log_path, event_bus)
