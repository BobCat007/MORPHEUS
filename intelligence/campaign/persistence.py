"""Restore in-memory campaign context from persisted analysis events."""

from dataclasses import fields
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


def restore_campaign_context(
    detector: CampaignDetector,
    events: Iterable[Dict[str, Any]],
) -> set:
    """Restore detector memory without publishing events or invoking responses."""
    latest: Dict[str, Tuple[str, Dict[str, Any]]] = {}

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
        timestamp = event.get("timestamp")
        timestamp = timestamp if isinstance(timestamp, str) else ""
        current = latest.get(session_id)
        if current is None or timestamp >= current[0]:
            latest[session_id] = (timestamp, data)

    restored = set()
    for session_id, (_, data) in sorted(
        latest.items(), key=lambda item: (item[1][0], item[0])
    ):
        try:
            session = ReconstructedSession(
                **_known_fields(ReconstructedSession, data.get("session"))
            )
        except (TypeError, ValueError):
            continue

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
                    intents.append(IntentResult(**_known_fields(IntentResult, item)))
                except (TypeError, ValueError):
                    continue

        detector.observe(session=session, fingerprint=fingerprint, intents=intents)
        restored.add(session_id)

    return restored
