
"""FastAPI application for the MORPHEUS security dashboard."""

import asyncio
import hmac
import json
import os
from collections import Counter
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, Header, HTTPException, Query, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field

from core.storage.event_store import EventStore
from pathlib import Path
from incidents.service import (
    VALID_STATUSES,
    get_incident,
    list_incidents,
    update_incident_status,
)


ALERT_EVENT_TYPE = "morpheus.alert.created"
ANALYSIS_EVENT_TYPE = "morpheus.intelligence.analysis"
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


def _newest_first(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Sort events newest first using their stored timestamps."""

    return sorted(
        events,
        key=lambda event: str(event.get("timestamp") or ""),
        reverse=True,
    )


def _alert_events(storage_path: str) -> List[Dict[str, Any]]:
    """Return stored alert events, newest first."""

    events = [
        event
        for event in _read_events(storage_path)
        if event.get("event_type") == ALERT_EVENT_TYPE
        and isinstance(event.get("data"), dict)
    ]
    return _newest_first(events)



def _analysis_events(storage_path: str) -> List[Dict[str, Any]]:
    """Return valid intelligence-analysis events, newest first.

    Risk score breaks ties when events have the same timestamp.
    """

    events = []

    for event in _read_events(storage_path):
        if event.get("event_type") != ANALYSIS_EVENT_TYPE:
            continue

        data = event.get("data")
        if not isinstance(data, dict):
            continue

        session = data.get("session")
        risk = data.get("risk_assessment")

        if not isinstance(session, dict) or not isinstance(risk, dict):
            continue

        events.append(event)

    def sort_key(event: Dict[str, Any]) -> Any:
        data = event.get("data", {})
        risk = data.get("risk_assessment", {})
        score = risk.get("score", 0)

        try:
            score = float(score)
        except (TypeError, ValueError):
            score = 0

        return (
            str(event.get("timestamp") or ""),
            score,
        )

    return sorted(events, key=sort_key, reverse=True)


def _analysis_severity(event: Dict[str, Any]) -> str:
    """Get the normalized severity from an analysis event."""

    data = event.get("data", {})
    risk = data.get("risk_assessment", {})
    severity = risk.get("severity", "unknown")

    if not isinstance(severity, str):
        return "unknown"

    return severity.strip().lower()


def create_app(
    storage_path: Optional[str] = None,
    write_token: Optional[str] = None,
) -> FastAPI:
    """Create an application using a specified or configured event store."""

    resolved_path = storage_path or os.getenv(
        "MORPHEUS_STORAGE_PATH",
        "data/events.jsonl",
    )

    application = FastAPI(
        title="MORPHEUS API",
        description=(
            "Security alerts, analyzed sessions, and incident management API."
        ),
        version="1.1.0",
    )
    application.state.storage_path = resolved_path

    @application.websocket("/api/v1/stream")
    async def event_stream(websocket: WebSocket) -> None:
        """Stream newly appended JSONL events; REST remains the history source."""
        await websocket.accept()
        await websocket.send_json({"type": "stream.connected"})

        event_path = Path(application.state.storage_path)
        handle = None
        inode = None
        offset = 0
        pending = b""
        max_event_bytes = 1024 * 1024

        try:
            while True:
                try:
                    current = event_path.stat()
                except FileNotFoundError:
                    await asyncio.sleep(0.1)
                    continue

                if (
                    handle is None
                    or inode != current.st_ino
                    or current.st_size < offset
                ):
                    if handle is not None:
                        handle.close()
                    handle = event_path.open("rb")
                    inode = current.st_ino
                    offset = current.st_size
                    handle.seek(offset)
                    pending = b""
                elif current.st_size > offset:
                    handle.seek(offset)
                    chunk = handle.read(current.st_size - offset)
                    offset += len(chunk)
                    pending += chunk

                    while b"\n" in pending:
                        line, pending = pending.split(b"\n", 1)
                        if not line.strip() or len(line) > max_event_bytes:
                            continue
                        try:
                            event = json.loads(line)
                        except (UnicodeDecodeError, json.JSONDecodeError):
                            continue
                        if isinstance(event, dict):
                            await websocket.send_json(event)

                    if len(pending) > max_event_bytes:
                        pending = b""

                await asyncio.sleep(0.1)
        except WebSocketDisconnect:
            pass
        finally:
            if handle is not None:
                handle.close()

    @application.get("/api/v1/health")
    def health() -> Dict[str, str]:
        """Return application health without exposing filesystem details."""

        return {"status": "ok", "service": "morpheus-api"}

    @application.get("/api/v1/dashboard")
    def dashboard() -> Dict[str, Any]:
        """Summarize alerts, analyzed sessions, and incident statuses."""

        storage = application.state.storage_path
        alerts = _alert_events(storage)
        sessions = _analysis_events(storage)

        severity_counts = Counter(
            str(event["data"].get("severity", "unknown")).lower()
            for event in alerts
        )
        session_severity_counts = Counter(
            _analysis_severity(event) for event in sessions
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
            "total_analyzed_sessions": len(sessions),
            "sessions_by_severity": {
                severity: session_severity_counts.get(severity, 0)
                for severity in SEVERITIES
            },
            "total_incidents": len(incident_records),
            "incidents_by_status": {
                status: incident_status_counts.get(status, 0)
                for status in VALID_STATUSES
            },
            "latest_alerts": alerts[:10],
            "latest_sessions": sessions[:10],
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

    @application.get("/api/v1/sessions")
    def sessions(
        severity: Optional[str] = Query(None),
        limit: int = Query(100, ge=1, le=500),
    ) -> Dict[str, Any]:
        """List analyzed sessions, optionally filtered by risk severity."""

        if severity is not None:
            severity = severity.strip().lower()
            if severity not in SEVERITIES:
                raise HTTPException(
                    status_code=400,
                    detail="Severity must be low, medium, high, or critical.",
                )

        results = _analysis_events(application.state.storage_path)

        if severity is not None:
            results = [
                event
                for event in results
                if _analysis_severity(event) == severity
            ]

        return {
            "count": len(results[:limit]),
            "total_matching": len(results),
            "items": results[:limit],
        }

    @application.get("/api/v1/sessions/{session_id}")
    def session_detail(session_id: str) -> Dict[str, Any]:
        """Return an analyzed session by its session identifier."""

        results = _analysis_events(application.state.storage_path)

        for event in results:
            data = event.get("data", {})
            session = data.get("session", {})

            if session.get("session_id") == session_id:
                return event

        raise HTTPException(status_code=404, detail="Analyzed session not found.")

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
        supplied_token: Optional[str] = Header(
            None, alias="X-Morpheus-Write-Token"
        ),
    ) -> Dict[str, Any]:
        """Append an incident status change after authenticating the caller."""

        expected_token = (
            write_token
            if write_token is not None
            else os.getenv("MORPHEUS_API_WRITE_TOKEN", "")
        )

        if not expected_token:
            raise HTTPException(
                status_code=503,
                detail="Incident updates are disabled: write token is not configured.",
            )


        if not supplied_token or not hmac.compare_digest(
            supplied_token, expected_token
        ):
            raise HTTPException(
                status_code=401,
                detail="Missing or invalid incident write token.",
                headers={"WWW-Authenticate": "Bearer"},
            )

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
