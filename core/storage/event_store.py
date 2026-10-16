"""JSONL-backed event storage for MORPHEUS."""

import json
from pathlib import Path
from typing import Any, Dict, List


class EventStore:
    """Simple JSONL event store for MORPHEUS events."""

    def __init__(self, file_path: str) -> None:
        self.file_path = Path(file_path)
        self.file_path.parent.mkdir(parents=True, exist_ok=True)

    def save(self, event: Dict[str, Any]) -> None:
        """Append an event to the persistent event store."""

        with self.file_path.open("a", encoding="utf-8") as file:
            file.write(json.dumps(event) + "\n")

    def read_all(self) -> List[Dict[str, Any]]:
        """Read all stored events in insertion order.

        Blank lines are ignored. Invalid JSON or records that aren't JSON
        objects raise ValueError with the relevant line number.
        """

        if not self.file_path.exists():
            return []

        events: List[Dict[str, Any]] = []

        with self.file_path.open("r", encoding="utf-8") as file:
            for line_number, line in enumerate(file, start=1):
                if not line.strip():
                    continue

                try:
                    event = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(
                        "Invalid JSON in event store at line {}.".format(
                            line_number
                        )
                    ) from exc

                if not isinstance(event, dict):
                    raise ValueError(
                        "Event store record at line {} must be a JSON "
                        "object.".format(line_number)
                    )

                events.append(event)

        return events

    def count(self) -> int:
        """Return the number of non-empty stored event records."""

        if not self.file_path.exists():
            return 0

        with self.file_path.open("r", encoding="utf-8") as file:
            return sum(1 for line in file if line.strip())
