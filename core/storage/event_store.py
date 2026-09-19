import json
from pathlib import Path
from typing import Dict, Any


class EventStore:
    """Simple JSONL event store for MORPHEUS events."""

    def __init__(self, file_path: str) -> None:
        self.file_path = Path(file_path)
        self.file_path.parent.mkdir(parents=True, exist_ok=True)

    def save(self, event: Dict[str, Any]) -> None:
        """Append an event to the persistent event store."""

        with self.file_path.open("a", encoding="utf-8") as file:
            file.write(json.dumps(event) + "\n")

    def count(self) -> int:
        """Return the number of stored events."""

        if not self.file_path.exists():
            return 0

        with self.file_path.open("r", encoding="utf-8") as file:
            return sum(1 for line in file if line.strip())
