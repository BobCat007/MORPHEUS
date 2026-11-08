"""Persistent JSONL queue for reliable MORPHEUS sensor delivery."""
import json
import os
import tempfile
from pathlib import Path
from threading import RLock
from typing import Any, Dict, Iterable, List, Set

_LOCKS_GUARD = RLock()
_PATH_LOCKS = {}


def _lock_for(path: Path) -> RLock:
    key = str(path.resolve())
    with _LOCKS_GUARD:
        if key not in _PATH_LOCKS:
            _PATH_LOCKS[key] = RLock()
        return _PATH_LOCKS[key]


class SensorDeliveryQueue:
    """Durable local queue. Network delivery and retries are separate stages."""

    def __init__(self, file_path: str) -> None:
        if not file_path:
            raise ValueError("file_path must not be empty")
        self.file_path = Path(file_path).expanduser().resolve()
        self.file_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = _lock_for(self.file_path)
        with self._lock:
            if not self.file_path.exists():
                self._write_records([])

    @staticmethod
    def _validate_event(event: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(event, dict):
            raise TypeError("Queued event must be a dictionary")
        event_id = event.get("event_id")
        if event_id is None or not str(event_id).strip():
            raise ValueError("Queued event must contain a non-empty event_id")
        try:
            normalized = json.loads(json.dumps(event))
        except (TypeError, ValueError) as exc:
            raise ValueError("Queued event must be JSON serializable") from exc
        normalized["event_id"] = str(normalized["event_id"])
        return normalized

    def _read_records(self) -> List[Dict[str, Any]]:
        if not self.file_path.exists():
            return []
        records = []
        with self.file_path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(
                        "Invalid JSON in sensor queue at line {}".format(line_number)
                    ) from exc
                if not isinstance(record, dict):
                    raise ValueError(
                        "Sensor queue record at line {} must be an object".format(
                            line_number
                        )
                    )
                records.append(self._validate_event(record))
        return records

    def _write_records(self, records: Iterable[Dict[str, Any]]) -> None:
        fd, temporary_name = tempfile.mkstemp(
            prefix=self.file_path.name + ".",
            suffix=".tmp",
            dir=str(self.file_path.parent),
        )
        temporary_path = Path(temporary_name)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                for record in records:
                    handle.write(json.dumps(record, separators=(",", ":")) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(str(temporary_path), str(self.file_path))
            try:
                directory_fd = os.open(str(self.file_path.parent), os.O_RDONLY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            except OSError:
                pass
        except Exception:
            try:
                temporary_path.unlink()
            except FileNotFoundError:
                pass
            raise

    def enqueue(self, event: Dict[str, Any]) -> bool:
        """Queue one event; return False if its event_id is already pending."""
        return self.enqueue_many([event]) == 1

    def enqueue_many(self, events: Iterable[Dict[str, Any]]) -> int:
        normalized = [self._validate_event(event) for event in events]
        if not normalized:
            return 0
        with self._lock:
            records = self._read_records()
            known_ids = {record["event_id"] for record in records}
            added = []
            for event in normalized:
                if event["event_id"] not in known_ids:
                    known_ids.add(event["event_id"])
                    added.append(event)
            if added:
                self._write_records(records + added)
            return len(added)

    def pending(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Return oldest pending records without removing them."""
        if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
            raise ValueError("limit must be a positive integer")
        with self._lock:
            return self._read_records()[:limit]

    def acknowledge(self, event_ids: Iterable[str]) -> int:
        """Remove only explicitly acknowledged IDs; return number removed."""
        acknowledged: Set[str] = {
            str(event_id) for event_id in event_ids if event_id is not None
        }
        if not acknowledged:
            return 0
        with self._lock:
            records = self._read_records()
            remaining = [
                record for record in records
                if record["event_id"] not in acknowledged
            ]
            removed = len(records) - len(remaining)
            if removed:
                self._write_records(remaining)
            return removed

    def count(self) -> int:
        with self._lock:
            return len(self._read_records())
