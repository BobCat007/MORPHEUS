from core.events.bus import EventBus
from telemetry.cowrie.parser import CowrieParser


def ingest_cowrie_events(log_path: str, event_bus: EventBus) -> int:
    """Read Cowrie events and publish them to the MORPHEUS EventBus."""

    parser = CowrieParser(log_path)
    event_count = 0

    for event in parser.read_events():
        event_bus.publish(event)
        event_count += 1

    return event_count
