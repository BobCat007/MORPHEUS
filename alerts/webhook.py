"""Optional HTTP webhook delivery for MORPHEUS security alerts."""

import json
import logging
import queue
import threading
from typing import Optional
from urllib.error import HTTPError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from core.events.model import MorpheusEvent


ALERT_EVENT_TYPE = "morpheus.alert.created"
LOGGER = logging.getLogger(__name__)

_QUEUE_SIZE = 100
_MAX_ATTEMPTS = 3
_RETRY_BACKOFF_SECONDS = (0.5, 1.0)


class WebhookHandler:
    """Deliver alert events synchronously or through an optional worker."""

    def __init__(
        self,
        webhook_url: Optional[str],
        timeout: float = 5.0,
    ) -> None:
        if not isinstance(timeout, (int, float)) or isinstance(timeout, bool):
            raise ValueError("Webhook timeout must be a number.")

        if not 0.1 <= timeout <= 30.0:
            raise ValueError("Webhook timeout must be between 0.1 and 30 seconds.")

        self.webhook_url = (
            webhook_url.strip() if isinstance(webhook_url, str) else ""
        )
        self.timeout = float(timeout)

        if self.webhook_url:
            parsed = urlparse(self.webhook_url)
            if (
                parsed.scheme not in ("http", "https")
                or not parsed.netloc
                or parsed.hostname is None
                or parsed.username is not None
                or parsed.password is not None
            ):
                raise ValueError(
                    "Webhook URL must be a valid HTTP or HTTPS URL "
                    "without embedded credentials."
                )

        self._queue = queue.Queue(maxsize=_QUEUE_SIZE)
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._worker = None
        self._stopping = False

    @property
    def enabled(self) -> bool:
        """Whether a webhook destination has been configured."""
        return bool(self.webhook_url)

    def start(self) -> None:
        """Start the optional background delivery worker."""
        if not self.enabled:
            return

        with self._lock:
            if self._worker is not None:
                return

            self._stopping = False
            self._stop_event.clear()
            self._worker = threading.Thread(
                target=self._worker_loop,
                name="morpheus-webhook",
                daemon=True,
            )
            self._worker.start()

    def stop(self, timeout: float = 10.0) -> None:
        """Stop the worker, allowing queued events a bounded drain period."""
        if not isinstance(timeout, (int, float)) or isinstance(timeout, bool):
            raise ValueError("Webhook shutdown timeout must be a number.")
        if timeout < 0:
            raise ValueError("Webhook shutdown timeout cannot be negative.")

        with self._lock:
            worker = self._worker
            if worker is None:
                return
            self._stopping = True
            self._stop_event.set()

        worker.join(timeout=float(timeout))

        with self._lock:
            if not worker.is_alive():
                self._worker = None
            else:
                LOGGER.warning(
                    "Webhook worker did not stop within %.1f seconds; "
                    "pending deliveries may be lost.",
                    timeout,
                )

    def handle(self, event: MorpheusEvent) -> None:
        """Accept an alert without blocking when background mode is active."""
        if event.event_type != ALERT_EVENT_TYPE or not self.enabled:
            return

        with self._lock:
            worker = self._worker
            if worker is not None:
                if self._stopping:
                    LOGGER.warning(
                        "Webhook delivery skipped during shutdown."
                    )
                    return
                try:
                    self._queue.put_nowait(event)
                except queue.Full:
                    LOGGER.warning(
                        "Webhook queue is full; alert delivery was dropped."
                    )
                return

        # Preserve the existing synchronous behavior unless start() was called.
        self._deliver_once(event)

    def _build_request(self, event: MorpheusEvent) -> Request:
        payload = json.dumps(event.to_dict()).encode("utf-8")
        return Request(
            self.webhook_url,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "MORPHEUS-Webhook/1.0",
            },
            method="POST",
        )

    def _deliver_once(self, event: MorpheusEvent):
        """Return (success, retryable) for one HTTP attempt."""
        try:
            request = self._build_request(event)
            with urlopen(request, timeout=self.timeout) as response:
                status = getattr(response, "status", None)
                if status is not None and not 200 <= status < 300:
                    retryable = status == 429 or status >= 500
                    return False, retryable

            LOGGER.info("MORPHEUS alert webhook delivered successfully.")
            return True, False

        except HTTPError as exc:
            return False, exc.code == 429 or exc.code >= 500
        except Exception:
            # Never log exception text: it may contain a sensitive URL.
            return False, True

    def _deliver_with_retries(self, event: MorpheusEvent) -> None:
        for attempt in range(_MAX_ATTEMPTS):
            success, retryable = self._deliver_once(event)
            if success:
                return

            if not retryable:
                LOGGER.warning(
                    "MORPHEUS alert webhook delivery failed with a "
                    "non-retryable HTTP response."
                )
                return

            if attempt < _MAX_ATTEMPTS - 1:
                delay = _RETRY_BACKOFF_SECONDS[attempt]
                self._stop_event.wait(delay)

        LOGGER.warning(
            "MORPHEUS alert webhook delivery failed after %s attempts.",
            _MAX_ATTEMPTS,
        )

    def _worker_loop(self) -> None:
        while True:
            try:
                event = self._queue.get(timeout=0.1)
            except queue.Empty:
                if self._stop_event.is_set():
                    return
                continue

            try:
                self._deliver_with_retries(event)
            finally:
                self._queue.task_done()
