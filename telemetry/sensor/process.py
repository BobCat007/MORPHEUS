"""Standalone Cowrie sensor process for distributed MORPHEUS deployments."""

import logging
import os
import signal
import threading
from pathlib import Path

from core.events.bus import EventBus
from telemetry.cowrie.live import CowrieLogFollower
from telemetry.cowrie.live_pipeline import COWRIE_EVENT_TYPES
from telemetry.sensor.queue import SensorDeliveryQueue
from telemetry.sensor.runtime import SensorHeartbeatClient, SensorRuntime
from telemetry.sensor.sender import SensorHttpSender


LOG = logging.getLogger("morpheus.sensor")


def required_env(name):
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError("Required environment variable is missing: " + name)
    return value


def run_sensor():
    collector_url = required_env("MORPHEUS_COLLECTOR_URL")
    sensor_id = required_env("MORPHEUS_SENSOR_ID")
    token_file = Path(required_env("MORPHEUS_SENSOR_TOKEN_FILE")).expanduser()
    cowrie_log = Path(
        os.environ.get(
            "MORPHEUS_COWRIE_LOG",
            "deployment/cowrie/var/log/cowrie/cowrie.json",
        )
    ).expanduser()
    queue_path = Path(
        os.environ.get(
            "MORPHEUS_SENSOR_QUEUE",
            "~/.local/state/morpheus/sensor-queue.jsonl",
        )
    ).expanduser()

    if not token_file.is_file():
        raise RuntimeError("Sensor token file does not exist: {}".format(token_file))

    sensor_token = token_file.read_text(encoding="utf-8").strip()
    if not sensor_token:
        raise RuntimeError("Sensor token file is empty")

    if not cowrie_log.is_file():
        raise RuntimeError("Cowrie log file does not exist: {}".format(cowrie_log))

    heartbeat_interval = float(
        os.environ.get("MORPHEUS_SENSOR_HEARTBEAT_INTERVAL", "30")
    )
    poll_interval = float(
        os.environ.get("MORPHEUS_SENSOR_POLL_INTERVAL", "5")
    )
    log_poll_interval = float(
        os.environ.get("MORPHEUS_COWRIE_LOG_POLL_INTERVAL", "0.25")
    )

    stop_event = threading.Event()
    event_bus = EventBus()
    queue = SensorDeliveryQueue(str(queue_path))

    def enqueue_event(event):
        queue.enqueue(event.to_dict())

    for event_type in COWRIE_EVENT_TYPES:
        event_bus.subscribe(event_type, enqueue_event)

    sender = SensorHttpSender(
        queue=queue,
        collector_url=collector_url,
        sensor_id=sensor_id,
        sensor_token=sensor_token,
    )
    heartbeat = SensorHeartbeatClient(
        collector_url=collector_url,
        sensor_id=sensor_id,
        sensor_token=sensor_token,
    )
    runtime = SensorRuntime(
        sender=sender,
        heartbeat_client=heartbeat,
        heartbeat_interval_seconds=heartbeat_interval,
        poll_interval_seconds=poll_interval,
    )

    follower = CowrieLogFollower(
        log_path=str(cowrie_log),
        event_bus=event_bus,
        poll_interval=log_poll_interval,
        start_at_end=os.environ.get(
            "MORPHEUS_SENSOR_START_AT_END", "true"
        ).lower() in ("1", "true", "yes"),
    )

    def request_stop(signum, frame):
        LOG.info("Received signal %s; stopping sensor", signum)
        stop_event.set()

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)

    def follow_cowrie():
        try:
            follower.run(stop_event)
        except Exception:
            LOG.exception("Cowrie log follower stopped unexpectedly")
            stop_event.set()

    follower_thread = threading.Thread(
        target=follow_cowrie,
        name="morpheus-cowrie-follower",
        daemon=True,
    )

    LOG.info("Starting sensor %s", sensor_id)
    LOG.info("Cowrie log: %s", cowrie_log)
    LOG.info("Persistent queue: %s", queue_path)
    LOG.info("Collector: %s", collector_url)
    LOG.info("Events already pending in queue: %s", queue.count())

    try:
        follower_thread.start()
        runtime.run_forever(stop_event)
    finally:
        stop_event.set()
        follower_thread.join(timeout=5)
        follower.close()
        sender.close()
        heartbeat.close()
        LOG.info("Sensor stopped; %s events remain queued", queue.count())


def main():
    logging.basicConfig(
        level=os.environ.get("MORPHEUS_SENSOR_LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    run_sensor()


if __name__ == "__main__":
    main()
