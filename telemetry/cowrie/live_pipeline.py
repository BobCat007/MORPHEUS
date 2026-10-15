from threading import Event
from typing import Optional

from core.events.bus import EventBus
from core.storage.event_store import EventStore
from core.storage.handler import EventStorageHandler
from deception.control.controller import DeceptionController
from intelligence.handler import IntelligenceHandler
from telemetry.cowrie.live import CowrieLogFollower


COWRIE_EVENT_TYPES = (
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
)


def run_live_cowrie_pipeline(
    log_path: str,
    storage_path: str,
    stop_event: Event,
    poll_interval: float = 0.25,
    start_at_end: bool = True,
    deception_controller: Optional[DeceptionController] = None,
    adaptive_deception_enabled: bool = False,
) -> None:
    """Follow live Cowrie telemetry until stop_event is set.

    Existing log history is skipped by default. Set start_at_end=False
    to process existing records as well.
    """
    event_bus = EventBus()

    event_store = EventStore(storage_path)
    storage_handler = EventStorageHandler(event_store)
    intelligence_handler = IntelligenceHandler(
        event_bus,
        deception_controller=deception_controller,
        adaptive_deception_enabled=adaptive_deception_enabled,
    )

    for event_type in COWRIE_EVENT_TYPES:
        event_bus.subscribe(event_type, storage_handler.handle)
        event_bus.subscribe(event_type, intelligence_handler.handle)

    event_bus.subscribe(
        "morpheus.intelligence.analysis",
        storage_handler.handle,
    )

    follower = CowrieLogFollower(
        log_path=log_path,
        event_bus=event_bus,
        poll_interval=poll_interval,
        start_at_end=start_at_end,
    )
    follower.run(stop_event)
