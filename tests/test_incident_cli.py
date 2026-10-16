
"""CLI tests for MORPHEUS incident management."""

from core.storage.event_store import EventStore
import morpheus


def test_incident_cli_lists_shows_and_updates_incident(tmp_path, capsys):
    storage_path = tmp_path / "events.jsonl"
    EventStore(str(storage_path)).save(
        {
            "event_type": "morpheus.alert.created",
            "source": "morpheus.alerting",
            "timestamp": "2026-10-16T10:00:00+00:00",
            "data": {
                "alert_id": "cli-alert-001",
                "session_id": "cli-session-001",
                "severity": "critical",
                "risk_score": 95,
                "source_ip": "192.0.2.50",
                "title": "Critical-risk session detected",
                "description": "CLI integration test.",
            },
        }
    )

    common = ["--storage-path", str(storage_path)]
    incident_id = "MORPHEUS-INC-cli-alert-001"

    result = morpheus.main(["incidents", "list"] + common)
    output = capsys.readouterr()

    assert result == 0
    assert incident_id in output.out
    assert "critical" in output.out
    assert "Total incidents: 1" in output.out

    result = morpheus.main(
        [
            "incidents",
            "status",
        ]
        + common
        + [
            "--incident-id",
            incident_id,
            "--status",
            "acknowledged",
            "--actor",
            "cli-analyst",
            "--note",
            "Reviewed from CLI.",
        ]
    )
    output = capsys.readouterr()

    assert result == 0
    assert "Incident status updated successfully." in output.out
    assert "Status: acknowledged" in output.out

    result = morpheus.main(
        ["incidents", "show"]
        + common
        + ["--incident-id", incident_id]
    )
    output = capsys.readouterr()

    assert result == 0
    assert "Status: acknowledged" in output.out
    assert "open -> acknowledged by cli-analyst" in output.out
    assert "Note: Reviewed from CLI." in output.out


def test_incident_cli_reports_missing_incident(tmp_path, capsys):
    result = morpheus.main(
        [
            "incidents",
            "show",
            "--storage-path",
            str(tmp_path / "events.jsonl"),
            "--incident-id",
            "missing-incident",
        ]
    )
    output = capsys.readouterr()

    assert result == 1
    assert "Error:" in output.err
    assert "missing-incident" in output.err
