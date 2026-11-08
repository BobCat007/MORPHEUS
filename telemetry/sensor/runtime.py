"""Runtime coordinator for MORPHEUS distributed sensors."""

import threading
import time
from typing import Any, Dict, Optional

import httpx


class SensorHeartbeatClient:
    """Send authenticated heartbeats to the central MORPHEUS collector."""

    def __init__(
        self,
        collector_url: str,
        sensor_id: str,
        sensor_token: str,
        timeout: float = 10.0,
        client: Optional[Any] = None,
    ) -> None:
        if not collector_url or not collector_url.strip():
            raise ValueError("collector_url must not be empty")
        if not sensor_id or not sensor_id.strip():
            raise ValueError("sensor_id must not be empty")
        if not sensor_token or not sensor_token.strip():
            raise ValueError("sensor_token must not be empty")
        if timeout <= 0:
            raise ValueError("timeout must be positive")

        self.url = collector_url.rstrip("/") + "/api/v1/sensors/heartbeat"
        self.headers = {
            "X-Morpheus-Sensor-ID": sensor_id,
            "X-Morpheus-Sensor-Token": sensor_token,
        }
        self.timeout = float(timeout)
        self._owns_client = client is None
        self.client = client or httpx.Client(timeout=self.timeout)

    def heartbeat(self) -> Dict[str, Any]:
        response = self.client.post(
            self.url,
            headers=self.headers,
            timeout=self.timeout,
        )
        response.raise_for_status()
        return {
            "status": "sent",
            "http_status": response.status_code,
        }

    def close(self) -> None:
        if self._owns_client:
            self.client.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()


class SensorRuntime:
    """Coordinate queued event delivery and periodic sensor heartbeats."""

    def __init__(
        self,
        sender: Any,
        heartbeat_client: SensorHeartbeatClient,
        heartbeat_interval_seconds: float = 30.0,
        poll_interval_seconds: float = 5.0,
        clock=time.monotonic,
    ) -> None:
        if heartbeat_interval_seconds <= 0:
            raise ValueError("heartbeat interval must be positive")
        if poll_interval_seconds <= 0:
            raise ValueError("poll interval must be positive")

        self.sender = sender
        self.heartbeat_client = heartbeat_client
        self.heartbeat_interval = float(heartbeat_interval_seconds)
        self.poll_interval = float(poll_interval_seconds)
        self._clock = clock
        self._next_heartbeat = 0.0
        self._last_heartbeat_error = None

    def run_once(self) -> Dict[str, Any]:
        """Send a heartbeat when due and attempt to flush queued events."""

        now = self._clock()
        heartbeat_result = {"status": "not_due"}

        if now >= self._next_heartbeat:
            try:
                heartbeat_result = self.heartbeat_client.heartbeat()
                self._last_heartbeat_error = None
            except Exception as exc:
                self._last_heartbeat_error = "{}: {}".format(
                    type(exc).__name__, exc
                )
                heartbeat_result = {
                    "status": "failed",
                    "error": self._last_heartbeat_error,
                }

            # Schedule the next attempt even after a failure. A later cycle
            # retries automatically without terminating the sensor process.
            self._next_heartbeat = now + self.heartbeat_interval

        try:
            delivery_result = self.sender.flush()
        except Exception as exc:
            delivery_result = {
                "status": "error",
                "error": "{}: {}".format(type(exc).__name__, exc),
            }

        return {
            "heartbeat": heartbeat_result,
            "delivery": delivery_result,
        }

    def run_forever(self, stop_event: threading.Event) -> None:
        """Run until the supplied event is set."""

        if stop_event is None:
            raise ValueError("stop_event is required")

        while not stop_event.is_set():
            self.run_once()
            stop_event.wait(self.poll_interval)
