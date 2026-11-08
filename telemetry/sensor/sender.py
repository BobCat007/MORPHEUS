"""HTTP transport for reliably delivering queued MORPHEUS sensor events."""
import time
from typing import Any, Callable, Dict, Optional

import httpx

from telemetry.sensor.queue import SensorDeliveryQueue


class SensorHttpSender:
    """Send queued events to a MORPHEUS collector with bounded retry/backoff.

    Events are removed from the local queue only after an explicit collector
    acknowledgement with status ``accepted`` or ``duplicate``.
    """

    def __init__(
        self,
        queue: SensorDeliveryQueue,
        collector_url: str,
        sensor_id: str,
        sensor_token: str,
        batch_size: int = 100,
        max_attempts: int = 3,
        base_backoff_seconds: float = 1.0,
        max_backoff_seconds: float = 30.0,
        timeout: float = 10.0,
        client: Optional[Any] = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if not collector_url or not collector_url.strip():
            raise ValueError("collector_url must not be empty")
        if not sensor_id or not sensor_id.strip():
            raise ValueError("sensor_id must not be empty")
        if not sensor_token or not sensor_token.strip():
            raise ValueError("sensor_token must not be empty")
        if not isinstance(batch_size, int) or isinstance(batch_size, bool):
            raise ValueError("batch_size must be an integer")
        if batch_size < 1 or batch_size > 100:
            raise ValueError("batch_size must be between 1 and 100")
        if not isinstance(max_attempts, int) or isinstance(max_attempts, bool):
            raise ValueError("max_attempts must be an integer")
        if max_attempts < 1:
            raise ValueError("max_attempts must be at least 1")
        if base_backoff_seconds < 0 or max_backoff_seconds < 0:
            raise ValueError("backoff values must not be negative")
        if timeout <= 0:
            raise ValueError("timeout must be positive")

        self.queue = queue
        self.collector_url = collector_url.rstrip("/") + "/api/v1/sensors/events"
        self.headers = {
            "X-Morpheus-Sensor-ID": sensor_id,
            "X-Morpheus-Sensor-Token": sensor_token,
        }
        self.batch_size = batch_size
        self.max_attempts = max_attempts
        self.base_backoff_seconds = float(base_backoff_seconds)
        self.max_backoff_seconds = float(max_backoff_seconds)
        self.timeout = float(timeout)
        self._sleep = sleep
        self._owns_client = client is None
        self.client = client or httpx.Client(timeout=self.timeout)

    def close(self) -> None:
        """Close the HTTP client if this sender created it."""
        if self._owns_client:
            self.client.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def _post_batch(self, events):
        response = self.client.post(
            self.collector_url,
            json={"events": events},
            headers=self.headers,
            timeout=self.timeout,
        )
        return response

    @staticmethod
    def _validated_acknowledgements(response_json, submitted_ids):
        """Validate the complete ack structure before acknowledging anything."""
        if not isinstance(response_json, dict):
            raise ValueError("Collector response must be a JSON object")
        acknowledgements = response_json.get("acknowledgements")
        if not isinstance(acknowledgements, list):
            raise ValueError("Collector response has no acknowledgement list")

        submitted = set(submitted_ids)
        acknowledged = set()
        for item in acknowledgements:
            if not isinstance(item, dict):
                raise ValueError("Malformed collector acknowledgement")
            event_id = item.get("event_id")
            status = item.get("status")
            if not isinstance(event_id, str) or not event_id:
                raise ValueError("Acknowledgement event_id must be a string")
            if status not in ("accepted", "duplicate"):
                raise ValueError("Unknown acknowledgement status")
            if event_id not in submitted:
                raise ValueError("Collector acknowledged an unsubmitted event")
            acknowledged.add(event_id)
        return acknowledged

    def flush(self) -> Dict[str, Any]:
        """Attempt to deliver the oldest batch; preserve anything not acked.

        Retries transient HTTP failures and malformed responses up to
        ``max_attempts``. HTTP 4xx responses other than 408 and 429 are treated
        as permanent request/authentication errors and are not retried.
        """
        events = self.queue.pending(self.batch_size)
        if not events:
            return {
                "status": "empty",
                "sent": 0,
                "acknowledged": 0,
                "remaining": self.queue.count(),
                "attempts": 0,
            }

        submitted_ids = [str(event["event_id"]) for event in events]
        acknowledged_ids = set()
        attempts = 0
        last_error = None

        for attempt in range(1, self.max_attempts + 1):
            attempts = attempt
            retryable = True
            remaining_events = [
                event for event in events
                if str(event["event_id"]) not in acknowledged_ids
            ]
            if not remaining_events:
                break

            try:
                response = self._post_batch(remaining_events)
                status_code = int(response.status_code)

                if status_code < 200 or status_code >= 300:
                    last_error = "Collector returned HTTP {}".format(status_code)
                    retryable = (
                        status_code in (408, 429) or status_code >= 500
                    )
                    if not retryable:
                        break
                else:
                    response_json = response.json()
                    batch_ids = [
                        str(event["event_id"]) for event in remaining_events
                    ]
                    newly_acknowledged = self._validated_acknowledgements(
                        response_json, batch_ids
                    )
                    if newly_acknowledged:
                        self.queue.acknowledge(newly_acknowledged)
                        acknowledged_ids.update(newly_acknowledged)

                    if len(acknowledged_ids) == len(submitted_ids):
                        last_error = None
                        break

                    last_error = "Collector acknowledgement was incomplete"

            except (httpx.HTTPError, ValueError, TypeError, KeyError) as exc:
                last_error = "{}: {}".format(type(exc).__name__, exc)
                retryable = True
            except Exception as exc:
                # Preserve queued data even for unexpected transport/client errors.
                last_error = "{}: {}".format(type(exc).__name__, exc)
                retryable = True

            if attempt < self.max_attempts and retryable:
                delay = min(
                    self.base_backoff_seconds * (2 ** (attempt - 1)),
                    self.max_backoff_seconds,
                )
                if delay:
                    self._sleep(delay)
            elif not retryable:
                break

        remaining = self.queue.count()
        acknowledged_count = len(acknowledged_ids)
        if acknowledged_count == len(submitted_ids):
            status = "delivered"
        elif acknowledged_count:
            status = "partial"
        else:
            status = "pending"

        return {
            "status": status,
            "sent": len(events),
            "acknowledged": acknowledged_count,
            "remaining": remaining,
            "attempts": attempts,
            "error": last_error,
        }
