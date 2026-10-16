
"""FastAPI application for the MORPHEUS security dashboard."""

import os
from collections import Counter
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field

from core.storage.event_store import EventStore
from incidents.service import (
    VALID_STATUSES,
    get_incident,
    list_incidents,
    update_incident_status,
)


ALERT_EVENT_TYPE = "morpheus.alert.created"
SEVERITIES = ("low", "medium", "high", "critical")


class IncidentStatusUpdate(BaseModel):
    """Validated request body for changing an incident's status."""

    status: str = Field(..., min_length=1, max_length=32)
    actor: str = Field("analyst", min_length=1, max_length=128)
    note: Optional[str] = Field(None, max_length=2000)


def _read_events(storage_path: str) -> List[Dict[str, Any]]:
    """Read the configured event store without exposing internal errors."""

    try:
        return EventStore(storage_path).read_all()
    except (OSError, ValueError):
        raise HTTPException(
            status_code=500,
            detail="Unable to read the MORPHEUS event store.",
        )


def _alert_events(storage_path: str) -> List[Dict[str, Any]]:
    """Return stored alert events, newest first."""

    events = [
        event
        for event in _read_events(storage_path)
        if event.get("event_type") == ALERT_EVENT_TYPE
        and isinstance(event.get("data"), dict)
    ]
    return sorted(
        events,
        key=lambda event: str(event.get("timestamp") or ""),
        reverse=True,
    )


def create_app(storage_path: Optional[str] = None) -> FastAPI:
    """Create an application using a specified or configured event store."""

    resolved_path = storage_path or os.getenv(
        "MORPHEUS_STORAGE_PATH",
        "data/events.jsonl",
    )

    application = FastAPI(
        title="MORPHEUS API",
        description="Security alert and incident management API.",
        version="1.0.0",
    )
    application.state.storage_path = resolved_path

    @application.get("/api/v1/health")
    def health() -> Dict[str, str]:
        """Return application health without exposing filesystem details."""

        return {"status": "ok", "service": "morpheus-api"}

    @application.get("/api/v1/dashboard")
    def dashboard() -> Dict[str, Any]:
        """Summarize alert severity and incident lifecycle status."""

        storage = application.state.storage_path
        alerts = _alert_events(storage)

        severity_counts = Counter(
            event["data"].get("severity", "unknown")
            for event in alerts
        )
        incident_records = list_incidents(storage)
        incident_status_counts = Counter(
            incident.get("status", "unknown")
            for incident in incident_records
        )

        return {
            "total_alerts": len(alerts),
            "alerts_by_severity": {
                severity: severity_counts.get(severity, 0)
                for severity in SEVERITIES
            },
            "total_incidents": len(incident_records),
            "incidents_by_status": {
                status: incident_status_counts.get(status, 0)
                for status in VALID_STATUSES
            },
            "latest_alerts": alerts[:10],
        }

    @application.get("/api/v1/alerts")
    def alerts(
        severity: Optional[str] = Query(None),
        limit: int = Query(100, ge=1, le=500),
    ) -> Dict[str, Any]:
        """List stored alerts, optionally filtered by severity."""

        if severity is not None:
            severity = severity.strip().lower()
            if severity not in SEVERITIES:
                raise HTTPException(
                    status_code=400,
                    detail="Severity must be low, medium, high, or critical.",
                )

        results = _alert_events(application.state.storage_path)

        if severity is not None:
            results = [
                event
                for event in results
                if str(event["data"].get("severity", "")).lower() == severity
            ]

        return {
            "count": len(results[:limit]),
            "total_matching": len(results),
            "items": results[:limit],
        }

    @application.get("/api/v1/incidents")
    def incidents(
        status: Optional[str] = Query(None),
        limit: int = Query(100, ge=1, le=500),
    ) -> Dict[str, Any]:
        """List incidents, optionally filtered by lifecycle status."""

        if status is not None:
            status = status.strip().lower()
            if status not in VALID_STATUSES:
                raise HTTPException(
                    status_code=400,
                    detail="Invalid incident status.",
                )

        try:
            results = list_incidents(application.state.storage_path)
        except (OSError, ValueError):
            raise HTTPException(
                status_code=500,
                detail="Unable to read the MORPHEUS event store.",
            )

        if status is not None:
            results = [
                incident
                for incident in results
                if incident.get("status") == status
            ]

        return {
            "count": len(results[:limit]),
            "total_matching": len(results),
            "items": results[:limit],
        }

    @application.get("/api/v1/incidents/{incident_id}")
    def incident_detail(incident_id: str) -> Dict[str, Any]:
        """Return one incident and its status history."""

        try:
            return get_incident(
                application.state.storage_path,
                incident_id,
            )
        except LookupError:
            raise HTTPException(status_code=404, detail="Incident not found.")
        except (OSError, ValueError):
            raise HTTPException(
                status_code=500,
                detail="Unable to read the MORPHEUS event store.",
            )

    @application.patch("/api/v1/incidents/{incident_id}/status")
    def change_incident_status(
        incident_id: str,
        request: IncidentStatusUpdate,
    ) -> Dict[str, Any]:
        """Append an incident status change to the event store."""

        try:
            return update_incident_status(
                storage_path=application.state.storage_path,
                incident_id=incident_id,
                status=request.status,
                actor=request.actor,
                note=request.note,
            )
        except LookupError:
            raise HTTPException(status_code=404, detail="Incident not found.")
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        except OSError:
            raise HTTPException(
                status_code=500,
                detail="Unable to update the MORPHEUS incident.",
            )

    return application


app = create_app()
