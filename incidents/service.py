
"""Append-only incident lifecycle management for MORPHEUS."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from core.storage.event_store import EventStore


ALERT_EVENT_TYPE = "morpheus.alert.created"
STATUS_EVENT_TYPE = "morpheus.incident.status_changed"
VALID_STATUSES = ("open", "acknowledged", "investigating", "resolved")


def _incident_id(alert_id: str) -> str:
    """Return a stable incident ID for an alert."""

    return "MORPHEUS-INC-{}".format(alert_id)


def _timestamp() -> str:
    """Return the current UTC timestamp."""

    return datetime.now(timezone.utc).isoformat()


def list_incidents(storage_path: str) -> List[Dict[str, Any]]:
    """Return incidents reconstructed from alerts and status history."""

    store = EventStore(storage_path)
    incidents: Dict[str, Dict[str, Any]] = {}

    for event in store.read_all():
        event_type = event.get("event_type")
        data = event.get("data")

        if not isinstance(data, dict):
            continue

        if event_type == ALERT_EVENT_TYPE:
            alert_id = data.get("alert_id")
            if not isinstance(alert_id, str) or not alert_id.strip():
                continue

            incident_id = _incident_id(alert_id)
            if incident_id in incidents:
                # Keep the original incident and append any later alert
                # details only through explicit lifecycle events.
                continue

            created_at = event.get("timestamp") or data.get("created_at") or ""
            incidents[incident_id] = {
                "incident_id": incident_id,
                "alert_id": alert_id,
                "session_id": data.get("session_id"),
                "severity": data.get("severity", "unknown"),
                "risk_score": data.get("risk_score", 0),
                "source_ip": data.get("source_ip"),
                "title": data.get("title", "MORPHEUS security alert"),
                "description": data.get("description", ""),
                "created_at": created_at,
                "updated_at": created_at,
                "status": "open",
                "history": [],
            }

        elif event_type == STATUS_EVENT_TYPE:
            incident_id = data.get("incident_id")
            incident = incidents.get(incident_id)

            if incident is None:
                # Do not apply lifecycle records without a known alert.
                continue

            new_status = data.get("to_status")
            if new_status not in VALID_STATUSES:
                continue

            record = {
                "timestamp": event.get("timestamp", ""),
                "from_status": data.get("from_status"),
                "to_status": new_status,
                "actor": data.get("actor", "analyst"),
                "note": data.get("note"),
            }
            incident["history"].append(record)
            incident["status"] = new_status
            incident["updated_at"] = event.get("timestamp", "")

    return sorted(
        incidents.values(),
        key=lambda incident: incident["updated_at"],
        reverse=True,
    )


def get_incident(storage_path: str, incident_id: str) -> Dict[str, Any]:
    """Return one incident by ID."""

    if not isinstance(incident_id, str) or not incident_id.strip():
        raise ValueError("incident_id must be a non-empty string.")

    for incident in list_incidents(storage_path):
        if incident["incident_id"] == incident_id:
            return incident

    raise LookupError(
        "No incident found with ID {!r}.".format(incident_id)
    )


def update_incident_status(
    storage_path: str,
    incident_id: str,
    status: str,
    actor: str = "analyst",
    note: Optional[str] = None,
    changed_at: Optional[str] = None,
) -> Dict[str, Any]:
    """Append a status change and return the updated incident.

    Statuses may be changed to any supported value. Reopening a resolved
    incident is allowed and remains visible in the audit history.
    """

    if not isinstance(status, str):
        raise ValueError("status must be one of: {}.".format(
            ", ".join(VALID_STATUSES)
        ))

    status = status.strip().lower()
    if status not in VALID_STATUSES:
        raise ValueError(
            "Invalid status {!r}. Choose one of: {}.".format(
                status, ", ".join(VALID_STATUSES)
            )
        )

    if not isinstance(actor, str) or not actor.strip():
        raise ValueError("actor must be a non-empty string.")

    if note is not None and not isinstance(note, str):
        raise ValueError("note must be a string.")

    incident = get_incident(storage_path, incident_id)

    if incident["status"] == status:
        raise ValueError(
            "Incident is already in status {!r}.".format(status)
        )

    timestamp = changed_at or _timestamp()
    event_store = EventStore(storage_path)
    event_store.save(
        {
            "event_type": STATUS_EVENT_TYPE,
            "source": "morpheus.incidents",
            "timestamp": timestamp,
            "data": {
                "incident_id": incident["incident_id"],
                "alert_id": incident["alert_id"],
                "session_id": incident["session_id"],
                "from_status": incident["status"],
                "to_status": status,
                "actor": actor.strip(),
                "note": note.strip() if isinstance(note, str) and note.strip() else None,
            },
        }
    )

    return get_incident(storage_path, incident_id)
