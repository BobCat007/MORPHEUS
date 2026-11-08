"""JSONL-backed event storage for MORPHEUS events."""

import json
import os
from pathlib import Path
from threading import RLock
from typing import Any, Dict, List, Tuple


# Locks are shared by all EventStore instances targeting the same path.
_LOCKS_GUARD = RLock()
_PATH_LOCKS = {}


def _lock_for(path: Path) -> RLock:
    key = str(path.resolve())
    with _LOCKS_GUARD:
        if key not in _PATH_LOCKS:
            _PATH_LOCKS[key] = RLock()
        return _PATH_LOCKS[key]


class EventStore:
    """Simple JSONL event store with coordinated, durable batch writes."""

    def __init__(self, file_path: str) -> None:
        self.file_path = Path(file_path).expanduser().resolve()
        self.file_path.parent.mkdir(parents=True, exist_ok=True)
        self._write_lock = _lock_for(self.file_path)

    def save(self, event: Dict[str, Any]) -> None:
        """Append one event."""
        record = json.dumps(event) + "\n"
        with self._write_lock:
            with self.file_path.open("a", encoding="utf-8") as file:
                file.write(record)
                file.flush()
                os.fsync(file.fileno())

    def save_many_unique(
        self, events: List[Dict[str, Any]]
    ) -> Tuple[List[str], List[str]]:
        """Append only unseen event IDs and report accepted and duplicate IDs.

        Existing IDs are reconstructed from the JSONL file while holding the
        shared path lock. This makes duplicate detection survive API restarts.
        """
        accepted = []
        duplicates = []

        with self._write_lock:
            known_ids = set()

            if self.file_path.exists():
                with self.file_path.open("r", encoding="utf-8") as file:
                    for line_number, line in enumerate(file, start=1):
                        if not line.strip():
                            continue
                        try:
                            stored = json.loads(line)
                        except json.JSONDecodeError as exc:
                            raise ValueError(
                                "Invalid JSON in event store at line {}.".format(
                                    line_number
                                )
                            ) from exc
                        if not isinstance(stored, dict):
                            raise ValueError(
                                "Event store record at line {} must be a JSON object.".format(
                                    line_number
                                )
                            )
                        event_id = stored.get("event_id")
                        if event_id is not None:
                            known_ids.add(str(event_id))

            pending_ids = set()
            for event in events:
                event_id = str(event["event_id"])
                if event_id in known_ids or event_id in pending_ids:
                    duplicates.append(event_id)
                else:
                    accepted.append(event)
                    pending_ids.add(event_id)

            if accepted:
                payload = "".join(
                    json.dumps(event) + "\n" for event in accepted
                )
                with self.file_path.open("a", encoding="utf-8") as file:
                    file.write(payload)
                    file.flush()
                    os.fsync(file.fileno())

        return (
            [str(event["event_id"]) for event in accepted],
            duplicates,
        )

    def read_all(self) -> List[Dict[str, Any]]:
        """Read all stored events in insertion order."""
        if not self.file_path.exists():
            return []

        events = []
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
                        "Event store record at line {} must be a JSON object.".format(
                            line_number
                        )
                    )
                events.append(event)
        return events

    def count(self) -> int:
        if not self.file_path.exists():
            return 0
        with self.file_path.open("r", encoding="utf-8") as file:
            return sum(1 for line in file if line.strip())
