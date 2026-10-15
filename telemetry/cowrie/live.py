import json
from pathlib import Path
from threading import Event
from typing import Optional, Tuple

from core.events.bus import EventBus
from telemetry.cowrie.parser import CowrieParser


class CowrieLogFollower:
    """Follow newly appended Cowrie JSONL events without replaying history."""

    def __init__(
        self,
        log_path: str,
        event_bus: EventBus,
        poll_interval: float = 0.25,
        start_at_end: bool = True,
    ) -> None:
        if poll_interval <= 0:
            raise ValueError("poll_interval must be greater than zero")

        self.log_path = Path(log_path)
        self.event_bus = event_bus
        self.poll_interval = poll_interval
        self.start_at_end = start_at_end
        self.parser = CowrieParser(str(self.log_path))

        self._file = None
        self._identity: Optional[Tuple[int, int]] = None
        self._pending = b""
        self._line_number = 0

    def _open(self, start_at_end: bool) -> bool:
        """Open the current log and optionally skip its existing contents."""
        try:
            stat = self.log_path.stat()
        except FileNotFoundError:
            return False

        handle = self.log_path.open("rb")
        if self._file is not None:
            self._file.close()

        self._file = handle
        self._identity = (stat.st_dev, stat.st_ino)
        self._pending = b""

        if start_at_end:
            handle.seek(0, 2)

        return True

    def _publish_complete_lines(self, data: bytes) -> int:
        """Publish complete newline-terminated JSON records only."""
        records = (self._pending + data).split(b"\n")
        self._pending = records.pop()

        published = 0

        for raw_line in records:
            self._line_number += 1
            line = raw_line.strip()

            if not line:
                continue

            try:
                raw_event = json.loads(line.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ValueError(
                    "Invalid Cowrie JSON record in live log near "
                    "stream line {}".format(self._line_number)
                ) from exc

            if not isinstance(raw_event, dict):
                raise ValueError(
                    "Cowrie log records must be JSON objects"
                )

            event = self.parser._normalize(raw_event)
            self.event_bus.publish(event)
            published += 1

        return published

    def poll_once(self) -> int:
        """Read and publish currently available complete log records."""
        try:
            stat = self.log_path.stat()
        except FileNotFoundError:
            return 0

        identity = (stat.st_dev, stat.st_ino)

        if self._file is None:
            if not self._open(self.start_at_end):
                return 0
            if self.start_at_end:
                return 0

        elif identity != self._identity:
            # The log was replaced during rotation. Read the new file
            # from its beginning so events in the new file are not skipped.
            if not self._open(start_at_end=False):
                return 0

        elif stat.st_size < self._file.tell():
            # The same log file was truncated or recreated in place.
            self._file.seek(0)
            self._pending = b""

        data = self._file.read()
        return self._publish_complete_lines(data)

    def run(self, stop_event: Event) -> None:
        """Follow the log until stop_event is set."""
        try:
            while not stop_event.is_set():
                self.poll_once()
                stop_event.wait(self.poll_interval)
        finally:
            self.close()

    def close(self) -> None:
        """Release the open log handle."""
        if self._file is not None:
            self._file.close()
            self._file = None
            self._identity = None
