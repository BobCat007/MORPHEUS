"""Restore in-memory campaign context from persisted analysis events."""

from dataclasses import fields, replace
from typing import Any, Dict, Iterable, List, Tuple

from intelligence.campaign.detector import CampaignDetector
from intelligence.fingerprint.model import AttackerFingerprint
from intelligence.intent.model import IntentResult
from intelligence.session.model import ReconstructedSession


def _known_fields(model: Any, payload: Any) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        return {}
    allowed = {item.name for item in fields(model)}
    return {key: value for key, value in payload.items() if key in allowed}


def _normalize_honeypot_id(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        return "default"
    return value.strip()


def qualified_session_id(honeypot_id: str, session_id: str) -> str:
    """Create an unambiguous internal session ID scoped to one sensor."""
    sensor = _normalize_honeypot_id(honeypot_id)
    return f"{len(sensor)}:{sensor}:{session_id}"


def restore_campaign_context(
    detector: CampaignDetector,
    events: Iterable[Dict[str, Any]],
    namespace_sessions: bool = False,
) -> set:
    """Restore detector memory without publishing events or invoking responses.

    When namespace_sessions is enabled, identical local session IDs from
    different honeypots are treated as separate sessions.
    """
    latest: Dict[Tuple[str, str], Tuple[str, Dict[str, Any]]] = {}

    for event in events:
        if not isinstance(event, dict):
            continue
        if event.get("event_type") != "morpheus.intelligence.analysis":
            continue

        data = event.get("data")
        if not isinstance(data, dict):
            continue

        session_data = data.get("session")
        if not isinstance(session_data, dict):
            continue

        session_id = session_data.get("session_id")
        if not isinstance(session_id, str) or not session_id:
            continue

        honeypot_id = _normalize_honeypot_id(data.get("honeypot_id"))
        key = (
            (honeypot_id, session_id)
            if namespace_sessions
            else ("default", session_id)
        )

        timestamp = event.get("timestamp")
        timestamp = timestamp if isinstance(timestamp, str) else ""

        current = latest.get(key)
        if current is None or timestamp >= current[0]:
            latest[key] = (timestamp, data)

    restored = set()

    for (honeypot_id, original_session_id), (_, data) in sorted(
        latest.items(),
        key=lambda item: (item[1][0], item[0]),
    ):
        try:
            session = ReconstructedSession(
                **_known_fields(ReconstructedSession, data.get("session"))
            )
        except (TypeError, ValueError):
            continue

        if namespace_sessions:
            session = replace(
                session,
                session_id=qualified_session_id(
                    honeypot_id,
                    original_session_id,
                ),
            )

        fingerprint = None
        fingerprint_data = data.get("fingerprint")

        if isinstance(fingerprint_data, dict):
            try:
                fingerprint = AttackerFingerprint(
                    **_known_fields(AttackerFingerprint, fingerprint_data)
                )
            except (TypeError, ValueError):
                fingerprint = None

        intents: List[IntentResult] = []
        intents_data = data.get("intents", [])

        if isinstance(intents_data, list):
            for item in intents_data:
                if not isinstance(item, dict):
                    continue
                try:
                    intents.append(
                        IntentResult(**_known_fields(IntentResult, item))
                    )
                except (TypeError, ValueError):
                    continue

        actual_honeypot_id = (
            honeypot_id
            if namespace_sessions
            else _normalize_honeypot_id(data.get("honeypot_id"))
        )

        detector.observe(
            session=session,
            fingerprint=fingerprint,
            intents=intents,
            honeypot_id=actual_honeypot_id,
        )

        restored.add(session.session_id)

    return restored
