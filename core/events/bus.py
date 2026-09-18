from collections import defaultdict
from typing import Callable, Dict, List

from core.events.model import MorpheusEvent
from core.events.validator import validate_event


EventHandler = Callable[[MorpheusEvent], None]


class EventBus:
    def __init__(self) -> None:
        self._handlers: Dict[str, List[EventHandler]] = defaultdict(list)

    def subscribe(self, event_type: str, handler: EventHandler) -> None:
        self._handlers[event_type].append(handler)

    def publish(self, event: MorpheusEvent) -> None:
        validate_event(event.to_dict())

        for handler in self._handlers.get(event.event_type, []):
            handler(event)
