"""Optional HTTP webhook delivery for MORPHEUS security alerts."""

import json
import logging
from typing import Optional
from urllib.error import HTTPError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from core.events.model import MorpheusEvent


ALERT_EVENT_TYPE = "morpheus.alert.created"
LOGGER = logging.getLogger(__name__)


class WebhookHandler:
    """Deliver alert events to an explicitly configured HTTP endpoint."""

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
            webhook_url.strip()
            if isinstance(webhook_url, str)
            else ""
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

    @property
    def enabled(self) -> bool:
        """Whether a webhook destination has been configured."""

        return bool(self.webhook_url)

    def handle(self, event: MorpheusEvent) -> None:
        """Send an alert event, keeping delivery failures isolated."""

        if event.event_type != ALERT_EVENT_TYPE or not self.enabled:
            return

        try:
            payload = json.dumps(event.to_dict()).encode("utf-8")
            request = Request(
                self.webhook_url,
                data=payload,
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "User-Agent": "MORPHEUS-Webhook/1.0",
                },
                method="POST",
            )

            with urlopen(request, timeout=self.timeout) as response:
                status = getattr(response, "status", None)
                if status is not None and not 200 <= status < 300:
                    LOGGER.warning(
                        "Webhook delivery returned HTTP status %s.",
                        status,
                    )
                    return

            LOGGER.info("MORPHEUS alert webhook delivered successfully.")

        except HTTPError as exc:
            LOGGER.warning(
                "MORPHEUS alert webhook returned HTTP status %s.",
                exc.code,
            )
        except Exception as exc:
            # Do not log the exception text: it may contain a sensitive URL.
            LOGGER.warning(
                "MORPHEUS alert webhook delivery failed (%s).",
                type(exc).__name__,
            )
