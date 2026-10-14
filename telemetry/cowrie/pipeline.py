from core.events.bus import EventBus
from core.storage.event_store import EventStore
from core.storage.handler import EventStorageHandler
from intelligence.handler import IntelligenceHandler
from telemetry.cowrie.ingest import ingest_cowrie_events


def run_cowrie_pipeline(log_path: str, storage_path: str) -> int:
    """Process Cowrie telemetry, persist raw events, and analyze sessions."""

    event_bus = EventBus()

    event_store = EventStore(storage_path)
    storage_handler = EventStorageHandler(event_store)
    intelligence_handler = IntelligenceHandler(event_bus)

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
        "cowrie.log.closed",
        "cowrie.session.closed",
    ]

    for event_type in event_types:
        event_bus.subscribe(event_type, storage_handler.handle)
        event_bus.subscribe(event_type, intelligence_handler.handle)

    # Persist generated intelligence events through the same event store.
    event_bus.subscribe(
        "morpheus.intelligence.analysis",
        storage_handler.handle,
    )

    return ingest_cowrie_events(log_path, event_bus)
