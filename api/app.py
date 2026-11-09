"""FastAPI application for the MORPHEUS security dashboard."""

import asyncio
import hmac
import json
import os
from collections import Counter
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone

from fastapi import FastAPI, Header, HTTPException, Query, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field

from core.events.validator import validate_event
from core.storage.event_store import EventStore
from intelligence.campaign.aggregator import CrossHoneypotAggregator
from intelligence.session.model import ReconstructedSession
from threat_intel.ioc.extractor import IOCExtractor
from purple_team.runner import PurpleTeamRunner
from purple_team.store import PurpleTeamRunStore
from incidents.service import (
    VALID_STATUSES,
    get_incident,
    list_incidents,
    update_incident_status,
)
from core.security.sensor_registry import (
    SensorAlreadyExists,
    SensorNotFound,
    SensorRegistry,
)

ALERT_EVENT_TYPE = "morpheus.alert.created"
ANALYSIS_EVENT_TYPE = "morpheus.intelligence.analysis"
SEVERITIES = ("low", "medium", "high", "critical")


class IncidentStatusUpdate(BaseModel):
    """Validated request body for changing an incident's status."""

    status: str = Field(..., min_length=1, max_length=32)
    actor: str = Field("analyst", min_length=1, max_length=128)
    note: Optional[str] = Field(None, max_length=2000)


class SensorEventBatch(BaseModel):
    """Validated batch submitted by an authenticated remote sensor."""

    events: List[Dict[str, Any]] = Field(..., min_length=1, max_length=100)

class SensorRegistration(BaseModel):
    sensor_id: str = Field(..., min_length=1, max_length=128)


class PurpleTeamRunRequest(BaseModel):
    scenario_id: str = Field(..., min_length=1, max_length=128)

def _read_events(storage_path: str) -> List[Dict[str, Any]]:
    """Read the configured event store without exposing internal errors."""
    try:
        return EventStore(storage_path).read_all()
    except (OSError, ValueError):
        raise HTTPException(
            status_code=500,
            detail="Unable to read the MORPHEUS event store.",
        )

def _read_platform_events(
    cowrie_storage_path: str,
    sensor_storage_path: str,
) -> List[Dict[str, Any]]:
    """Read Cowrie and remote sensor events without sharing their writers."""
    return (
        _read_events(cowrie_storage_path)
        + _read_events(sensor_storage_path)
    )

def _newest_first(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Sort events newest first using their stored timestamps."""
    return sorted(
        events,
        key=lambda event: str(event.get("timestamp") or ""),
        reverse=True,
    )


def _alert_events(
    storage_path: str,
    sensor_storage_path: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Return stored alert events, newest first."""
    events = [
        event
        for event in (
            _read_platform_events(storage_path, sensor_storage_path)
            if sensor_storage_path
            else _read_events(storage_path)
        )
        if event.get("event_type") == ALERT_EVENT_TYPE
        and isinstance(event.get("data"), dict)
    ]
    return _newest_first(events)

def _analysis_events(
    storage_path: str,
    sensor_storage_path: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Return valid intelligence-analysis events, newest first."""
    source_events = (
        _read_platform_events(storage_path, sensor_storage_path)
        if sensor_storage_path
        else _read_events(storage_path)
    )

    events = []
    for event in source_events:
        if event.get("event_type") != ANALYSIS_EVENT_TYPE:
            continue
        data = event.get("data")
        if not isinstance(data, dict):
            continue
        if not isinstance(data.get("session"), dict):
            continue
        if not isinstance(data.get("risk_assessment"), dict):
            continue
        events.append(event)

    def sort_key(event: Dict[str, Any]) -> Any:
        risk = event.get("data", {}).get("risk_assessment", {})
        try:
            score = float(risk.get("score", 0))
        except (TypeError, ValueError):
            score = 0
        return str(event.get("timestamp") or ""), score

    return sorted(events, key=sort_key, reverse=True)

def _analysis_severity(event: Dict[str, Any]) -> str:
    """Get the normalized severity from an analysis event."""
    risk = event.get("data", {}).get("risk_assessment", {})
    severity = risk.get("severity", "unknown")
    return severity.strip().lower() if isinstance(severity, str) else "unknown"


def create_app(
    storage_path: Optional[str] = None,
    write_token: Optional[str] = None,
    http_storage_path: Optional[str] = None,
    sensor_tokens: Optional[Dict[str, str]] = None,
    sensor_storage_path: Optional[str] = None,
    purple_team_storage_path: Optional[str] = None,
) -> FastAPI:
    """Create an application using specified or configured event stores."""
    resolved_path = storage_path or os.getenv(
        "MORPHEUS_STORAGE_PATH", "data/events.jsonl"
    )
    resolved_http_path = http_storage_path or os.getenv(
        "MORPHEUS_HTTP_EVENT_STORE", "data/http-events.jsonl"
    )

    cowrie_path = Path(resolved_path).expanduser().resolve()
    http_path = Path(resolved_http_path).expanduser().resolve()
    resolved_sensor_path = sensor_storage_path or os.getenv(
        "MORPHEUS_SENSOR_EVENT_STORE", "data/sensor-events.jsonl"
    )

    sensor_path = Path(resolved_sensor_path).expanduser().resolve()
    resolved_purple_path = purple_team_storage_path or os.getenv(
        "MORPHEUS_PURPLE_TEAM_STORE", "data/purple-team-runs.jsonl"
    )
    purple_path = Path(resolved_purple_path).expanduser().resolve()

    if len({cowrie_path, http_path, sensor_path, purple_path}) != 4:
        raise ValueError(
           "Cowrie, HTTP, and remote sensor and Purple Team data must use separate stores."
        )
    if cowrie_path == http_path:
        raise ValueError(
            "HTTP deception events must use a separate event store from Cowrie."
        )

    application = FastAPI(
        title="MORPHEUS API",
        description=(
            "Security alerts, analyzed sessions, and incident management API."
        ),
        version="1.1.0",
    )

    if sensor_tokens is None:
        raw_tokens = os.getenv("MORPHEUS_SENSOR_TOKENS", "")
        if raw_tokens:
            try:
                sensor_tokens = json.loads(raw_tokens)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    "MORPHEUS_SENSOR_TOKENS must contain valid JSON."
                ) from exc
        else:
            sensor_tokens = {}

    if not isinstance(sensor_tokens, dict) or any(
        not isinstance(sensor_id, str)
        or not sensor_id.strip()
        or len(sensor_id) > 128
        or not isinstance(token, str)
        or not token
        for sensor_id, token in sensor_tokens.items()
    ):
        raise ValueError("Invalid MORPHEUS sensor credentials configuration.")

    registry_path = os.getenv("MORPHEUS_SENSOR_REGISTRY") or str(
        sensor_path.with_name("sensor-registry.json")
    )

    application.state.sensor_registry = SensorRegistry(
        registry_path,
        initial_tokens=sensor_tokens,
    )

    try:
        heartbeat_timeout = int(
            os.getenv("MORPHEUS_SENSOR_HEARTBEAT_TIMEOUT_SECONDS", "90")
        )
    except ValueError as exc:
        raise ValueError(
            "MORPHEUS_SENSOR_HEARTBEAT_TIMEOUT_SECONDS must be an integer."
        ) from exc

    if heartbeat_timeout < 1:
        raise ValueError("Sensor heartbeat timeout must be positive.")

    application.state.sensor_heartbeat_timeout_seconds = heartbeat_timeout

    application.state.sensor_admin_token = os.getenv(
        "MORPHEUS_SENSOR_ADMIN_TOKEN",
        "",
    )

    application.state.storage_path = str(cowrie_path)
    application.state.http_storage_path = str(http_path)
    application.state.sensor_storage_path = str(sensor_path)
    application.state.sensor_tokens = dict(sensor_tokens)
    application.state.purple_team_runner = PurpleTeamRunner()
    application.state.purple_team_store = PurpleTeamRunStore(purple_path)

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

    def require_sensor_admin(supplied_token):
        expected = application.state.sensor_admin_token

        if not expected:
            raise HTTPException(
                status_code=503,
                detail="Sensor administration is not configured.",
            )

        if not supplied_token or not hmac.compare_digest(
            supplied_token, expected
        ):
            raise HTTPException(
                status_code=401,
                detail="Invalid sensor administrator credentials.",
            )

    @application.post("/api/v1/sensors", status_code=201)
    def register_sensor(
        request: SensorRegistration,
        admin_token: Optional[str] = Header(
            None,
            alias="X-Morpheus-Sensor-Admin-Token",
        ),
    ):
        require_sensor_admin(admin_token)

        try:
            token = application.state.sensor_registry.register(
                request.sensor_id
            )
        except SensorAlreadyExists:
            raise HTTPException(
                status_code=409,
                detail="Sensor is already registered.",
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc))

        return {
            "status": "registered",
            "sensor_id": request.sensor_id,
            "token": token,
            "message": "Store this token securely. It will not be shown again.",
        }

    @application.get("/api/v1/sensors")
    def list_sensors(
        admin_token: Optional[str] = Header(
            None,
            alias="X-Morpheus-Sensor-Admin-Token",
        ),
    ):
        require_sensor_admin(admin_token)

        return {
            "sensors": application.state.sensor_registry.list_sensors()
        }

    @application.post("/api/v1/sensors/heartbeat")
    def sensor_heartbeat(
        sensor_id: Optional[str] = Header(None, alias="X-Morpheus-Sensor-ID"),
        supplied_token: Optional[str] = Header(
            None, alias="X-Morpheus-Sensor-Token"
        ),
    ) -> Dict[str, Any]:
        """Record an authenticated remote sensor heartbeat."""
        if not application.state.sensor_registry.verify(
            sensor_id, supplied_token
        ):
            raise HTTPException(
                status_code=401,
                detail="Missing or invalid sensor credentials.",
            )

        try:
            timestamp = application.state.sensor_registry.heartbeat(sensor_id)
        except SensorNotFound:
            raise HTTPException(
                status_code=404,
                detail="Active sensor not found.",
            )
        except OSError as exc:
            raise HTTPException(
                status_code=500,
                detail="Unable to persist sensor heartbeat.",
            ) from exc

        return {
            "status": "recorded",
            "sensor_id": sensor_id,
            "last_seen": timestamp,
        }

    @application.get("/api/v1/sensors/health")
    def sensor_health() -> Dict[str, Any]:
        """Return sanitized online/offline status for registered sensors."""
        now = datetime.now(timezone.utc)
        timeout = application.state.sensor_heartbeat_timeout_seconds
        sensors = []

        for sensor in application.state.sensor_registry.list_sensor_health():
            last_seen = sensor.get("last_seen")
            online = False

            if sensor["status"] == "active" and last_seen:
                try:
                    timestamp = datetime.fromisoformat(
                        last_seen.replace("Z", "+00:00")
                    )
                    if timestamp.tzinfo is None:
                        timestamp = timestamp.replace(tzinfo=timezone.utc)

                    age = (now - timestamp).total_seconds()
                    online = 0 <= age <= timeout
                except (TypeError, ValueError):
                    online = False

            if sensor["status"] == "revoked":
                health_status = "revoked"
            else:
                health_status = "online" if online else "offline"

            sensors.append({
                "sensor_id": sensor["sensor_id"],
                "status": health_status,
                "online": online,
                "last_seen": last_seen,
            })

        return {
            "sensors": sensors,
            "online": sum(1 for item in sensors if item["status"] == "online"),
            "offline": sum(1 for item in sensors if item["status"] == "offline"),
            "revoked": sum(1 for item in sensors if item["status"] == "revoked"),
            "timeout_seconds": timeout,
        }

    @application.post("/api/v1/sensors/{sensor_id}/rotate")
    def rotate_sensor_token(
        sensor_id: str,
        admin_token: Optional[str] = Header(
            None,
            alias="X-Morpheus-Sensor-Admin-Token",
        ),
    ):
        require_sensor_admin(admin_token)

        try:
            token = application.state.sensor_registry.rotate(sensor_id)
        except SensorNotFound:
            raise HTTPException(
                status_code=404,
                detail="Active sensor not found.",
            )

        return {
            "status": "rotated",
            "sensor_id": sensor_id,
            "token": token,
            "message": "Store this token securely. It will not be shown again.",
        }

    @application.delete("/api/v1/sensors/{sensor_id}")
    def revoke_sensor(
        sensor_id: str,
        admin_token: Optional[str] = Header(
            None,
            alias="X-Morpheus-Sensor-Admin-Token",
        ),
    ):
        require_sensor_admin(admin_token)

        try:
            application.state.sensor_registry.revoke(sensor_id)
        except SensorNotFound:
            raise HTTPException(
                status_code=404,
                detail="Sensor not found.",
            )

        return {
            "status": "revoked",
            "sensor_id": sensor_id,
        }

    @application.post("/api/v1/sensors/events")
    def ingest_sensor_events(
        batch: SensorEventBatch,
        sensor_id: Optional[str] = Header(None, alias="X-Morpheus-Sensor-ID"),
        supplied_token: Optional[str] = Header(
            None, alias="X-Morpheus-Sensor-Token"
        ),
    ) -> Dict[str, Any]:
        """Authenticate a remote sensor and ingest its event batch."""
        if not application.state.sensor_registry.list_sensors():
            raise HTTPException(
                status_code=503,
                detail="Sensor ingestion is disabled: no sensors registered.",
            )

        if not application.state.sensor_registry.verify(
            sensor_id,
            supplied_token,
        ):
            raise HTTPException(
                status_code=401,
                detail="Missing or invalid sensor credentials.",
            )

        validated_events: List[Dict[str, Any]] = []

        # Validate the entire batch before writing anything.
        for incoming in batch.events:
            event = dict(incoming)
            try:
                validate_event(event)
            except (ValueError, TypeError) as exc:
                raise HTTPException(
                    status_code=422,
                    detail="Invalid event: {}".format(exc),
                ) from exc

            data = dict(event["data"])
            claimed_sensor = data.get("honeypot_id")

            if claimed_sensor and claimed_sensor != sensor_id:
                raise HTTPException(
                    status_code=422,
                    detail=(
                        "Event honeypot_id does not match "
                        "authenticated sensor."
                    ),
                )

            data["honeypot_id"] = sensor_id
            event["data"] = data
            validated_events.append(event)

        try:
            store = EventStore(application.state.sensor_storage_path)
            accepted_ids, duplicate_ids = store.save_many_unique(
                validated_events
            )
        except (OSError, TypeError, ValueError) as exc:
            raise HTTPException(
                status_code=500,
                detail="Unable to persist sensor events.",
            ) from exc

        accepted_set = set(accepted_ids)
        seen_ids = set()

        acknowledgements = []

        for event in validated_events:
            event_id = str(event["event_id"])

            if event_id in accepted_set and event_id not in seen_ids:
                status = "accepted"
            else:
                status = "duplicate"

            seen_ids.add(event_id)

            acknowledgements.append({
                "event_id": event["event_id"],
                "status": status,
            })

        return {
            "status": "accepted",
            "sensor_id": sensor_id,
            "accepted": len(accepted_ids),
            "event_ids": accepted_ids,
            "duplicate": len(duplicate_ids),
            "duplicate_event_ids": duplicate_ids,
            "acknowledgements": acknowledgements,
        }

    @application.get("/api/v1/dashboard")
    def dashboard() -> Dict[str, Any]:
        """Summarize alerts, analyzed sessions, and incident statuses."""
        storage = application.state.storage_path
        sensor_storage = application.state.sensor_storage_path
        alerts = _alert_events(storage, sensor_storage)
        sessions = _analysis_events(storage, sensor_storage)
        severity_counts = Counter(
            str(event["data"].get("severity", "unknown")).lower()
            for event in alerts
        )
        session_severity_counts = Counter(
            _analysis_severity(event) for event in sessions
        )
        incident_records = list_incidents(storage)
        incident_status_counts = Counter(
            incident.get("status", "unknown") for incident in incident_records
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
        results = _alert_events(
            application.state.storage_path,
            application.state.sensor_storage_path,
        )
        if severity is not None:
            results = [
                event for event in results
                if str(event["data"].get("severity", "")).lower() == severity
            ]
        return {
            "count": len(results[:limit]),
            "total_matching": len(results),
            "items": results[:limit],
        }

    @application.get("/api/v1/campaigns")
    def campaigns(
        honeypot_id: Optional[str] = Query(None),
        limit: int = Query(100, ge=1, le=500),
    ) -> Dict[str, Any]:
        """Reconstruct and list correlated campaigns across honeypots."""
        events = _analysis_events(
            application.state.storage_path,
            application.state.sensor_storage_path,
        )
        reconstructed = CrossHoneypotAggregator().rebuild(events)
        results = [asdict(campaign) for campaign in reconstructed]
        if honeypot_id is not None:
            requested_sensor = honeypot_id.strip()
            results = [
                campaign for campaign in results
                if requested_sensor in campaign.get("honeypot_ids", [])
            ]
        results.sort(
            key=lambda campaign: str(campaign.get("last_seen") or ""),
            reverse=True,
        )
        return {
            "count": len(results[:limit]),
            "total_matching": len(results),
            "items": results[:limit],
        }

    @application.get("/api/v1/http-events")
    def http_events(
        source_ip: Optional[str] = Query(None),
        honeypot_id: Optional[str] = Query(None),
        method: Optional[str] = Query(None),
        status_code: Optional[int] = Query(None, ge=100, le=599),
        limit: int = Query(100, ge=1, le=500),
    ) -> Dict[str, Any]:
        """List HTTP deception requests from the dedicated HTTP event store."""
        http_path = Path(application.state.http_storage_path)
        if not http_path.exists():
            results: List[Dict[str, Any]] = []
        else:
            results = [
                event for event in _read_events(str(http_path))
                if event.get("event_type") == "morpheus.http.request"
                and isinstance(event.get("data"), dict)
            ]
        if source_ip is not None:
            requested_ip = source_ip.strip()
            results = [
                event for event in results
                if str(
                    event["data"].get("client_ip")
                    or event["data"].get("source_ip")
                    or ""
                ) == requested_ip
            ]
        if honeypot_id is not None:
            requested_sensor = honeypot_id.strip()
            results = [
                event for event in results
                if str(event["data"].get("honeypot_id") or "")
                == requested_sensor
            ]
        if method is not None:
            requested_method = method.strip().upper()
            results = [
                event for event in results
                if str(event["data"].get("method") or "").upper()
                == requested_method
            ]
        if status_code is not None:
            results = [
                event for event in results
                if event["data"].get(
                    "response_status", event["data"].get("status_code")
                ) == status_code
            ]
        results = _newest_first(results)
        return {
            "count": len(results[:limit]),
            "total_matching": len(results),
            "items": results[:limit],
        }

    @application.get("/api/v1/iocs")
    def iocs(
        q: Optional[str] = Query(None, max_length=256),
        ioc_type: Optional[str] = Query(None, max_length=32),
        honeypot_id: Optional[str] = Query(None, max_length=128),
        limit: int = Query(100, ge=1, le=500),
    ) -> Dict[str, Any]:
        """Aggregate indicators across local and remote session analyses."""
        analyses = _analysis_events(
            application.state.storage_path,
            application.state.sensor_storage_path,
        )
        aggregated: Dict[tuple, Dict[str, Any]] = {}
        extractor = IOCExtractor()

        def is_path_only_domain(value: str, evidence_items: Any) -> bool:
            """Reject a domain only when every recorded occurrence is a file path."""
            found = False

            if not isinstance(evidence_items, list):
                return False

            for evidence in evidence_items:
                if not isinstance(evidence, str):
                    continue

                start = 0
                while True:
                    index = evidence.find(value, start)
                    if index < 0:
                        break

                    found = True
                    preceding = evidence[:index]

                    is_path = (
                        preceding.endswith(("/", "\\\\"))
                        and not preceding.endswith("://")
                    )
                    if not is_path:
                        return False

                    start = index + len(value)

            return found

        for event in analyses:
            data = event.get("data", {})
            timestamp = str(event.get("timestamp") or "")
            session = data.get("session") or {}
            session_id = str(session.get("session_id") or "")
            sensor_id = str(data.get("honeypot_id") or "default")
            indicators = data.get("indicators_of_compromise") or []

            # Reconstruct IOCs for legacy analysis events.
            if not indicators and isinstance(session, dict):
                commands = session.get("commands") or []
                if not isinstance(commands, list):
                    commands = []

                reconstructed = ReconstructedSession(
                    session_id=session_id or "legacy-session",
                    commands=[item for item in commands if isinstance(item, str)],
                )
                try:
                    indicators = [
                        asdict(item) for item in extractor.extract(reconstructed)
                    ]
                except (TypeError, ValueError, AttributeError):
                    indicators = []

            if not isinstance(indicators, list):
                continue

            for indicator in indicators:
                if not isinstance(indicator, dict):
                    continue
                value = indicator.get("value")
                kind = indicator.get("ioc_type")
                if not isinstance(value, str) or not value.strip():
                    continue
                if not isinstance(kind, str) or not kind.strip():
                    continue

                normalized_kind = kind.strip().lower()
                normalized_value = value.strip()
                if normalized_kind in {"domain", "ipv4", "md5", "sha256"}:
                    normalized_value = normalized_value.lower()

                if normalized_kind == "domain" and is_path_only_domain(
                    normalized_value,
                    indicator.get("context") or [],
                ):
                    continue

                key = (normalized_kind, normalized_value.lower())

                record = aggregated.get(key)
                if record is None:
                    record = {
                        "value": normalized_value,
                        "ioc_type": kind.strip().lower(),
                        "sources": [],
                        "honeypot_ids": [],
                        "session_ids": [],
                        "context": [],
                        "confidence": 0.0,
                        "occurrences": 0,
                        "first_seen": timestamp,
                        "last_seen": timestamp,
                    }
                    aggregated[key] = record

                record["occurrences"] += 1
                record["confidence"] = max(
                    record["confidence"],
                    min(1.0, max(0.0, float(indicator.get("confidence", 1.0)))),
                )

                source = str(indicator.get("source") or "unknown")
                if source not in record["sources"]:
                    record["sources"].append(source)
                if sensor_id not in record["honeypot_ids"]:
                    record["honeypot_ids"].append(sensor_id)
                if session_id and session_id not in record["session_ids"]:
                    record["session_ids"].append(session_id)

                context = indicator.get("context") or []
                if isinstance(context, list):
                    for evidence in context:
                        if (
                            isinstance(evidence, str)
                            and evidence
                            and evidence not in record["context"]
                            and len(record["context"]) < 20
                        ):
                            record["context"].append(evidence)

                if timestamp and (
                    not record["first_seen"] or timestamp < record["first_seen"]
                ):
                    record["first_seen"] = timestamp
                if timestamp > record["last_seen"]:
                    record["last_seen"] = timestamp

        results = list(aggregated.values())

        if ioc_type:
            requested_type = ioc_type.strip().lower()
            results = [
                item for item in results
                if item["ioc_type"] == requested_type
            ]

        if honeypot_id:
            requested_sensor = honeypot_id.strip()
            results = [
                item for item in results
                if requested_sensor in item["honeypot_ids"]
            ]

        if q:
            needle = q.strip().lower()
            results = [
                item for item in results
                if needle in item["value"].lower()
                or needle in item["ioc_type"]
                or any(needle in session for session in item["session_ids"])
                or any(needle in sensor for sensor in item["honeypot_ids"])
            ]

        results.sort(
            key=lambda item: (
                item["last_seen"],
                item["occurrences"],
                item["value"],
            ),
            reverse=True,
        )
        return {
            "count": len(results[:limit]),
            "total_matching": len(results),
            "total_unique": len(aggregated),
            "items": results[:limit],
        }

    @application.get("/api/v1/purple-team/scenarios")
    async def list_purple_team_scenarios():
        """List safe, non-executing Purple Team simulation scenarios."""
        items = application.state.purple_team_runner.list_scenarios()
        return {"count": len(items), "items": items}

    @application.post("/api/v1/purple-team/runs")
    async def run_purple_team_scenario(payload: PurpleTeamRunRequest):
        """Map synthetic commands and persist the Purple Team evaluation."""
        try:
            result = application.state.purple_team_runner.run(
                payload.scenario_id
            )
        except KeyError:
            raise HTTPException(
                status_code=404,
                detail="Purple Team scenario not found.",
            )
        application.state.purple_team_store.save(result)
        return result

    @application.get("/api/v1/purple-team/runs")
    async def list_purple_team_runs(
        limit: int = Query(100, ge=1, le=500),
    ):
        """List recent Purple Team simulation results."""
        items = application.state.purple_team_store.list_runs(limit=limit)
        return {"count": len(items), "items": items}

    @application.get("/api/v1/purple-team/runs/{run_id}")
    async def get_purple_team_run(run_id: str):
        """Retrieve one Purple Team simulation result."""
        result = application.state.purple_team_store.get_run(run_id)
        if result is None:
            raise HTTPException(
                status_code=404,
                detail="Purple Team run not found.",
            )
        return result

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
        results = _analysis_events(
            application.state.storage_path,
            application.state.sensor_storage_path,
        )
        if severity is not None:
            results = [
                event for event in results
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
        results = _analysis_events(
            application.state.storage_path,
            application.state.sensor_storage_path,
        )
        for event in results:
            session = event.get("data", {}).get("session", {})
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
                    status_code=400, detail="Invalid incident status."
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
                incident for incident in results
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
            return get_incident(application.state.storage_path, incident_id)
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
                detail=(
                    "Incident updates are disabled: "
                    "write token is not configured."
                ),
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
