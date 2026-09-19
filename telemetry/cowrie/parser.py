import json
from pathlib import Path
from typing import Iterator, Dict, Any

from core.events.model import MorpheusEvent


class CowrieParser:
    """Parse Cowrie JSON log events into MORPHEUS events."""

    def __init__(self, log_path: str) -> None:
        self.log_path = Path(log_path)

    def read_events(self) -> Iterator[MorpheusEvent]:
        """Read Cowrie JSONL log and yield normalized MORPHEUS events."""

        if not self.log_path.exists():
            raise FileNotFoundError(
                f"Cowrie log not found: {self.log_path}"
            )

        with self.log_path.open("r", encoding="utf-8") as log_file:
            for line_number, line in enumerate(log_file, start=1):
                line = line.strip()

                if not line:
                    continue

                try:
                    raw_event: Dict[str, Any] = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(
                        f"Invalid JSON at line {line_number}"
                    ) from exc

                yield self._normalize(raw_event)

    def _normalize(self, raw_event: Dict[str, Any]) -> MorpheusEvent:
        """Convert one Cowrie event into a MORPHEUS event."""

        return MorpheusEvent(
            event_type=raw_event.get("eventid", "unknown"),
            source="cowrie",
            data={
                key: value
                for key, value in raw_event.items()
                if key not in {"eventid", "uuid", "timestamp"}
            },
            timestamp=raw_event.get("timestamp"),
        )
