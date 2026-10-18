"""Regression test for rollback after Cowrie filesystem generation partially succeeds."""

from pathlib import Path

import pytest

from deception.control.controller import DeceptionController
from deception.control.cowrie import CowrieAdapter
from deception.control.model import DeceptionPlan
from deception.control.planner import DeceptionPlanner
from deception.personality.engine import PersonalityEngine
from intelligence.risk.model import RiskAssessment


class FakeLifecycle:
    def __init__(self):
        self.restart_calls = 0

    def is_running(self):
        return True

    def restart(self):
        self.restart_calls += 1


def test_controller_restores_files_when_config_write_fails_after_filesystem_write(
    tmp_path, monkeypatch
):
    """A failed config write must not leave the generated filesystem behind."""
    repo_root = Path(__file__).resolve().parents[1]
    baseline = repo_root / "deployment" / "cowrie" / "etc" / "cowrie-bundled-fs.pickle"
    if not baseline.is_file():
        pytest.skip("Cowrie bundled filesystem fixture is not available")

    config_path = tmp_path / "cowrie.cfg"
    output_path = tmp_path / "morpheus-fs.pickle"
    config_before = (
        b"# preserve this comment\n"
        b"[honeypot]\n"
        b"hostname = original-host\n"
        b"\n"
        b"[shell]\n"
        b"filesystem = /cowrie/original-fs.pickle\n"
    )
    filesystem_before = b"original filesystem bytes"
    config_path.write_bytes(config_before)
    output_path.write_bytes(filesystem_before)

    adapter = CowrieAdapter(
        config_path=str(config_path),
        filesystem_base_path=str(baseline),
        filesystem_output_path=str(output_path),
        filesystem_config_path="/cowrie/cowrie-git/etc/morpheus-fs.pickle",
    )

    def fail_config_write(_lines):
        raise OSError("simulated config write failure")

    monkeypatch.setattr(adapter, "_write_config", fail_config_write)
    lifecycle = FakeLifecycle()
    controller = DeceptionController(
        PersonalityEngine(),
        DeceptionPlanner(),
        adapter,
        lifecycle,
    )
    assessment = RiskAssessment(
        session_id="rollback-regression",
        score=95,
        severity="critical",
    )

    with pytest.raises(OSError, match="simulated config write failure"):
        controller.apply_for_risk(assessment)

    assert config_path.read_bytes() == config_before
    assert output_path.read_bytes() == filesystem_before
    assert lifecycle.restart_calls == 0
    assert controller._last_applied_plan is None
