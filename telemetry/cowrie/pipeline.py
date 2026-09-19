from core.events.bus import EventBus
from core.storage.event_store import EventStore
from core.storage.handler import EventStorageHandler
from telemetry.cowrie.ingest import ingest_cowrie_events


def run_cowrie_pipeline(log_path: str, storage_path: str) -> int:
    """Process Cowrie telemetry through MORPHEUS and persist events."""

    event_bus = EventBus()

    event_store = EventStore(storage_path)
    storage_handler = EventStorageHandler(event_store)

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

    return ingest_cowrie_events(log_path, event_bus)
