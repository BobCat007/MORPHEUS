import morpheus


def test_report_command_generates_incident_report(monkeypatch, capsys):
    captured = {}

    def fake_generate_incident_report_from_store(**kwargs):
        captured.update(kwargs)
        return {
            "session": {
                "session_id": "session-123",
            }
        }

    monkeypatch.setattr(
        morpheus,
        "generate_incident_report_from_store",
        fake_generate_incident_report_from_store,
    )

    result = morpheus.main(
        [
            "report",
            "--storage-path",
            "data/events.jsonl",
            "--session-id",
            "session-123",
            "--output",
            "reports/incident.json",
            "--generated-at",
            "2026-10-16T12:00:00+00:00",
        ]
    )

    captured_output = capsys.readouterr()

    assert result == 0
    assert captured == {
        "storage_path": "data/events.jsonl",
        "session_id": "session-123",
        "output_path": "reports/incident.json",
        "generated_at": "2026-10-16T12:00:00+00:00",
    }
    assert "Incident report generated successfully." in captured_output.out
    assert "Session ID: session-123" in captured_output.out
    assert "reports/incident.json" in captured_output.out
    assert captured_output.err == ""


def test_report_command_handles_missing_session(monkeypatch, capsys):
    def fake_generate_incident_report_from_store(**kwargs):
        raise LookupError("No stored analysis found for session 'missing'.")

    monkeypatch.setattr(
        morpheus,
        "generate_incident_report_from_store",
        fake_generate_incident_report_from_store,
    )

    result = morpheus.main(
        [
            "report",
            "--storage-path",
            "data/events.jsonl",
            "--session-id",
            "missing",
            "--output",
            "reports/incident.json",
        ]
    )

    captured_output = capsys.readouterr()

    assert result == 1
    assert "Error:" in captured_output.err
    assert "missing" in captured_output.err
    assert captured_output.out == ""
