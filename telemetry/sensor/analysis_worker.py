"""Analyze centrally collected raw events from independent MORPHEUS sensors."""

import json
import logging
import os
import signal
import time
from collections import defaultdict
from pathlib import Path

from core.events.bus import EventBus
from core.events.model import MorpheusEvent
from core.storage.event_store import EventStore
from intelligence.handler import IntelligenceHandler
from telemetry.cowrie.live_pipeline import COWRIE_EVENT_TYPES


LOG = logging.getLogger("morpheus.sensor.analysis")


def append_jsonl(path, record):
    """Append one complete JSONL record using a single O_APPEND write."""
    target = Path(path).expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)

    payload = (json.dumps(record, separators=(",", ":")) + "\n").encode("utf-8")
    fd = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        written = os.write(fd, payload)
        if written != len(payload):
            raise OSError("Incomplete JSONL append")
        os.fsync(fd)
    finally:
        os.close(fd)


class SensorAnalysisWorker:
    """Maintain isolated session reconstruction for every registered sensor."""

    def __init__(self, sensor_store_path, analysis_store_path):
        self.sensor_store = EventStore(str(sensor_store_path))
        self.analysis_store = EventStore(str(analysis_store_path))
        self.analysis_path = str(analysis_store_path)

        self.contexts = {}
        self.seen_event_ids = defaultdict(set)

    def _create_sensor_context(self, sensor_id):
        bus = EventBus()

        prior_analysis = [
            event
            for event in self.analysis_store.read_all()
            if event.get("event_type") == "morpheus.intelligence.analysis"
            and isinstance(event.get("data"), dict)
            and event["data"].get("honeypot_id") == sensor_id
        ]

        handler = IntelligenceHandler(
            event_bus=bus,
            prior_analysis_events=prior_analysis,
            honeypot_id=sensor_id,
            adaptive_deception_enabled=False,
        )

        # Persist analysis results without invoking adaptive response actions.
        bus.subscribe(
            "morpheus.intelligence.analysis",
            lambda event: append_jsonl(self.analysis_path, event.to_dict()),
        )

        for event_type in COWRIE_EVENT_TYPES:
            bus.subscribe(event_type, handler.handle)

        self.contexts[sensor_id] = {
            "bus": bus,
            "handler": handler,
        }

        LOG.info(
            "Initialized sensor analysis context: %s (restored %d sessions)",
            sensor_id,
            len(handler.processed_session_ids),
        )

    @staticmethod
    def _event_order(item):
        timestamp = item.get("timestamp")
        return timestamp if isinstance(timestamp, str) else ""

    def process_available_events(self):
        raw_events = self.sensor_store.read_all()
        grouped = defaultdict(list)

        for event in raw_events:
            if not isinstance(event, dict):
                continue

            event_type = event.get("event_type")
            data = event.get("data")

            if event_type not in COWRIE_EVENT_TYPES:
                continue
            if not isinstance(data, dict):
                continue

            sensor_id = data.get("honeypot_id")
            if not isinstance(sensor_id, str) or not sensor_id.strip():
                continue

            grouped[sensor_id.strip()].append(event)

        processed = 0

        # Initialize all contexts first so restored sessions are included
        # in the baseline and are not incorrectly counted as newly analyzed.
        for sensor_id in grouped:
            if sensor_id not in self.contexts:
                self._create_sensor_context(sensor_id)

        analyzed_before = sum(
            len(context["handler"].processed_session_ids)
            for context in self.contexts.values()
        )

        for sensor_id, events in grouped.items():
            context = self.contexts[sensor_id]
            events.sort(key=self._event_order)

            for raw in events:
                event_id = raw.get("event_id")
                if not isinstance(event_id, str) or not event_id:
                    continue

                if event_id in self.seen_event_ids[sensor_id]:
                    continue

                # Mark only after successful publication. A failed event can
                # therefore be retried on the next polling cycle.
                event = MorpheusEvent(
                    event_type=raw["event_type"],
                    source=raw.get("source", "sensor"),
                    data=dict(raw["data"]),
                    event_id=event_id,
                    timestamp=raw["timestamp"],
                )

                context["bus"].publish(event)
                self.seen_event_ids[sensor_id].add(event_id)
                processed += 1

        analyzed_after = sum(
            len(context["handler"].processed_session_ids)
            for context in self.contexts.values()
        )

        return {
            "raw_events_seen": len(raw_events),
            "events_processed": processed,
            "sensors": len(self.contexts),
            "newly_analyzed_sessions": analyzed_after - analyzed_before,
        }

    def run_forever(self, stop_event, poll_interval=2.0):
        LOG.info("Sensor analysis worker started")

        while not stop_event.is_set():
            try:
                result = self.process_available_events()
                if result["events_processed"]:
                    LOG.info("Worker cycle: %s", result)
            except Exception:
                LOG.exception("Sensor analysis cycle failed")

            stop_event.wait(poll_interval)

        LOG.info("Sensor analysis worker stopped")


def main():
    logging.basicConfig(
        level=os.environ.get("MORPHEUS_ANALYSIS_LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    sensor_path = os.environ.get(
        "MORPHEUS_SENSOR_EVENT_STORE", "data/sensor-events.jsonl"
    )
    analysis_path = os.environ.get(
        "MORPHEUS_STORAGE_PATH", "data/events.jsonl"
    )
    poll_interval = float(
        os.environ.get("MORPHEUS_ANALYSIS_POLL_INTERVAL", "2")
    )

    worker = SensorAnalysisWorker(sensor_path, analysis_path)
    stop_event = __import__("threading").Event()

    def stop(signum, frame):
        LOG.info("Received signal %s", signum)
        stop_event.set()

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)

    # Process existing records immediately, then continue polling.
    worker.run_forever(stop_event, poll_interval)


if __name__ == "__main__":
    main()
