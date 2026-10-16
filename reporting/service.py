"""Generate incident reports from persisted MORPHEUS analysis events."""

from typing import Any, Dict, Optional

from core.storage.event_store import EventStore
from reporting.incident_report import write_incident_report


def generate_incident_report_from_store(
    storage_path: str,
    session_id: str,
    output_path: str,
    generated_at: Optional[str] = None,
) -> Dict[str, Any]:
    """Find a session analysis in the event store and export its report.

    If multiple analysis events match the session, the most recently
    appended matching event is used.

    Raises:
        ValueError: If the requested session ID is empty.
        LookupError: If no matching analysis event is found.
        ValueError: If the event store contains malformed JSONL records.
    """

    if not isinstance(session_id, str) or not session_id.strip():
        raise ValueError("session_id must be a non-empty string.")

    event_store = EventStore(storage_path)
    matching_analysis = None

    for event in event_store.read_all():
        if event.get("event_type") != "morpheus.intelligence.analysis":
            continue

        analysis = event.get("data")
        if not isinstance(analysis, dict):
            continue

        session = analysis.get("session")
        if not isinstance(session, dict):
            continue

        if session.get("session_id") == session_id:
            matching_analysis = analysis

    if matching_analysis is None:
        raise LookupError(
            "No stored intelligence analysis found for session {!r}.".format(
                session_id
            )
        )

    return write_incident_report(
        analysis=matching_analysis,
        output_path=output_path,
        generated_at=generated_at,
    )
