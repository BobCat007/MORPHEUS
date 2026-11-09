"""Dedicated JSONL persistence for Purple Team runs."""

import json
import threading
from pathlib import Path


class PurpleTeamRunStore:
    def __init__(self, file_path):
        self.path = Path(file_path).expanduser().resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()

    def save(self, run):
        with self._lock:
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(run, sort_keys=True) + "\n")
                handle.flush()

    def list_runs(self, limit=100):
        if limit < 1 or not self.path.exists():
            return []

        with self._lock:
            items = []
            with self.path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    try:
                        item = json.loads(line)
                    except (json.JSONDecodeError, TypeError):
                        continue
                    if isinstance(item, dict):
                        items.append(item)

        return list(reversed(items[-limit:]))

    def get_run(self, run_id):
        return next(
            (
                item for item in self.list_runs(limit=100000)
                if item.get("run_id") == run_id
            ),
            None,
        )
