from core.events.model import MorpheusEvent
from core.storage.event_store import EventStore


class EventStorageHandler:
    """Persist MORPHEUS events received from the EventBus."""

    def __init__(self, store: EventStore) -> None:
        self.store = store

    def handle(self, event: MorpheusEvent) -> None:
        self.store.save(event.to_dict())
