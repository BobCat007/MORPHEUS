"""Build and export structured MORPHEUS incident reports."""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

from intelligence.session.model import (
    ReconstructedSession,
    SessionCommand,
)
from intelligence.timeline.reconstructor import TimelineReconstructor
from threat_intel.ioc.extractor import IOCExtractor


def _reconstruct_session(session_data: Mapping[str, Any]) -> ReconstructedSession:
    """Rebuild a session model from serialized intelligence analysis data."""

    session_id = session_data.get("session_id")
    if not isinstance(session_id, str) or not session_id.strip():
        raise ValueError("Analysis session must contain a non-empty session_id.")

    commands = session_data.get("commands", [])
    if not isinstance(commands, list):
        raise ValueError("Session commands must be a list.")

    command_events_data = session_data.get("command_events", [])
    if not isinstance(command_events_data, list):
        raise ValueError("Session command_events must be a list.")

    command_events = []
    for item in command_events_data:
        if not isinstance(item, Mapping):
            continue

        command = item.get("command")
        timestamp = item.get("timestamp")
        if isinstance(command, str) and isinstance(timestamp, str):
            command_events.append(
                SessionCommand(
                    command=command,
                    timestamp=timestamp,
                )
            )

    return ReconstructedSession(
        session_id=session_id,
        source_ip=session_data.get("source_ip"),
        protocol=session_data.get("protocol"),
        client_version=session_data.get("client_version"),
        hassh=session_data.get("hassh"),
        username=session_data.get("username"),
        authentication_success=bool(
            session_data.get("authentication_success", False)
        ),
        commands=[item for item in commands if isinstance(item, str)],
        command_events=command_events,
        start_time=session_data.get("start_time"),
        end_time=session_data.get("end_time"),
        duration_ms=session_data.get("duration_ms"),
    )


def _as_list(value: Any) -> list:
    """Return a list for optional collection fields."""

    return value if isinstance(value, list) else []


def build_incident_report(
    analysis: Mapping[str, Any],
    generated_at: Optional[str] = None,
) -> Dict[str, Any]:
    """Build a JSON-serializable incident report from an analysis payload."""

    if not isinstance(analysis, Mapping):
        raise TypeError("Analysis must be a mapping.")

    session_data = analysis.get("session")
    if not isinstance(session_data, Mapping):
        raise ValueError("Analysis must contain a session object.")

    session = _reconstruct_session(session_data)

    risk = analysis.get("risk_assessment")
    risk = risk if isinstance(risk, Mapping) else {}

    fingerprint = analysis.get("fingerprint")
    fingerprint = fingerprint if isinstance(fingerprint, Mapping) else {}

    campaign = analysis.get("campaign")
    campaign = campaign if isinstance(campaign, Mapping) else None

    timeline = TimelineReconstructor().build(session)
    iocs = IOCExtractor().extract(session)

    severity = risk.get("severity", "unknown")
    score = risk.get("score", 0)

    if generated_at is None:
        generated_at = datetime.now(timezone.utc).isoformat()

    return {
        "report_version": "1.0",
        "generated_at": generated_at,
        "incident": {
            "incident_id": "MORPHEUS-{}".format(session.session_id),
            "summary": (
                "MORPHEUS analyzed session {} from {}. "
                "The assessed risk is {} with a score of {}."
            ).format(
                session.session_id,
                session.source_ip or "an unknown source",
                severity,
                score,
            ),
            "severity": severity,
            "risk_score": score,
        },
        "session": {
            "session_id": session.session_id,
            "source_ip": session.source_ip,
            "protocol": session.protocol,
            "client_version": session.client_version,
            "hassh": session.hassh,
            "username": session.username,
            "authentication_success": session.authentication_success,
            "start_time": session.start_time,
            "end_time": session.end_time,
            "duration_ms": session.duration_ms,
            "command_count": len(session.commands),
            "commands": list(session.commands),
        },
        "fingerprint": dict(fingerprint),
        "intents": _as_list(analysis.get("intents")),
        "timeline": [
            {
                "timestamp": item.timestamp,
                "event_type": item.event_type,
                "session_id": item.session_id,
                "command": item.command,
                "technique_id": item.technique_id,
                "technique_name": item.technique_name,
                "tactic": item.tactic,
                "evidence": list(item.evidence),
            }
            for item in timeline
        ],
        "indicators_of_compromise": [
            {
                "value": item.value,
                "type": item.ioc_type,
                "source": item.source,
                "session_id": item.session_id,
                "confidence": item.confidence,
                "context": list(item.context),
            }
            for item in iocs
        ],
        "mitre_attack": _as_list(analysis.get("mitre_techniques")),
        "campaign": dict(campaign) if campaign is not None else None,
        "risk_assessment": dict(risk),
        "recommended_actions": _as_list(
            analysis.get("recommended_actions")
        ),
        "deception": (
            dict(analysis["deception"])
            if isinstance(analysis.get("deception"), Mapping)
            else {"enabled": False, "applied": False}
        ),
    }


def write_incident_report(
    analysis: Mapping[str, Any],
    output_path: str,
    generated_at: Optional[str] = None,
) -> Dict[str, Any]:
    """Write an incident report as UTF-8 JSON and return the report."""

    report = build_incident_report(
        analysis,
        generated_at=generated_at,
    )

    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)

    with destination.open("w", encoding="utf-8") as report_file:
        json.dump(
            report,
            report_file,
            indent=2,
            ensure_ascii=False,
        )
        report_file.write("\n")

    return report
