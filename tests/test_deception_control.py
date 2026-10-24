from configparser import ConfigParser
import os

import pytest

from deception.control.controller import DeceptionController
from deception.control.cowrie import CowrieAdapter
from deception.control.cowrie_lifecycle import CowrieLifecycle
from deception.control.model import DeceptionPlan
from deception.control.planner import DeceptionPlanner
from deception.personality.engine import PersonalityEngine
from intelligence.risk.model import RiskAssessment


class FakeAdapter:
    def __init__(self):
        self.applied_plan = None
        self.apply_calls = 0

    def apply(self, plan: DeceptionPlan) -> None:
        self.apply_calls += 1
        self.applied_plan = plan

    def current_state(self) -> DeceptionPlan:
        if self.applied_plan is None:
            raise ValueError("No plan has been applied.")
        return self.applied_plan

    def snapshot_state(self):
        return {"applied_plan": self.applied_plan}

    def restore_state(self, snapshot):
        self.applied_plan = snapshot["applied_plan"]


class FakeLifecycle:
    def __init__(self, running=True):
        self.running = running
        self.restart_called = False
        self.restart_calls = 0

    def is_running(self) -> bool:
        return self.running

    def restart(self) -> None:
        self.restart_called = True
        self.restart_calls += 1


def make_assessment(severity="high", score=70):
    return RiskAssessment(session_id="session-1", score=score, severity=severity)


def test_planner_builds_plan_from_personality():
    engine = PersonalityEngine()
    plan = DeceptionPlanner().build_plan(engine.select(make_assessment()))
    assert plan.personality_name == "enterprise_database"
    assert plan.hostname == "db-prod-01"
    assert plan.deception_level == 3
    assert "ssh" in plan.services
    assert plan.change_count() == 6


def test_controller_applies_plan_and_restarts_service():
    adapter, lifecycle = FakeAdapter(), FakeLifecycle()
    controller = DeceptionController(PersonalityEngine(), DeceptionPlanner(), adapter, lifecycle)
    plan = controller.apply_for_risk(make_assessment())
    assert plan.personality_name == "enterprise_database"
    assert adapter.applied_plan is plan
    assert lifecycle.restart_called is True


def test_controller_skips_restart_for_identical_plan():
    adapter, lifecycle = FakeAdapter(), FakeLifecycle()
    controller = DeceptionController(PersonalityEngine(), DeceptionPlanner(), adapter, lifecycle)
    first = controller.apply_for_risk(make_assessment())
    second = controller.apply_for_risk(make_assessment())
    assert first == second
    assert adapter.apply_calls == 1
    assert lifecycle.restart_calls == 1


def test_controller_applies_and_restarts_when_plan_changes():
    adapter, lifecycle = FakeAdapter(), FakeLifecycle()
    controller = DeceptionController(PersonalityEngine(), DeceptionPlanner(), adapter, lifecycle)
    first = controller.apply_for_risk(make_assessment(severity="high"))
    second = controller.apply_for_risk(make_assessment(severity="critical", score=95))
    assert first.personality_name != second.personality_name
    assert adapter.apply_calls == 2
    assert lifecycle.restart_calls == 2


def test_controller_checks_service_before_applying_plan():
    adapter, lifecycle = FakeAdapter(), FakeLifecycle(running=False)
    controller = DeceptionController(PersonalityEngine(), DeceptionPlanner(), adapter, lifecycle)
    with pytest.raises(RuntimeError, match="Deception service is not running"):
        controller.apply_for_risk(make_assessment())
    assert adapter.applied_plan is None
    assert lifecycle.restart_called is False


def test_controller_does_not_restart_if_adapter_fails():
    class BrokenAdapter(FakeAdapter):
        def apply(self, plan):
            raise OSError("configuration write failed")

    lifecycle = FakeLifecycle()
    controller = DeceptionController(
        PersonalityEngine(), DeceptionPlanner(), BrokenAdapter(), lifecycle
    )
    with pytest.raises(OSError, match="configuration write failed"):
        controller.apply_for_risk(make_assessment())
    assert lifecycle.restart_called is False


def test_controller_restores_previous_state_when_restart_fails():
    class FailFirstRestart(FakeLifecycle):
        def restart(self):
            self.restart_called = True
            self.restart_calls += 1
            if self.restart_calls == 1:
                raise RuntimeError("simulated restart failure")

    adapter, lifecycle = FakeAdapter(), FailFirstRestart()
    controller = DeceptionController(PersonalityEngine(), DeceptionPlanner(), adapter, lifecycle)
    with pytest.raises(RuntimeError, match="simulated restart failure"):
        controller.apply_for_risk(make_assessment())
    assert adapter.applied_plan is None
    assert lifecycle.restart_calls == 2
    assert controller._last_applied_plan is None


def test_controller_reports_when_rollback_and_recovery_fail():
    class AlwaysFailRestart(FakeLifecycle):
        def restart(self):
            self.restart_called = True
            self.restart_calls += 1
            raise RuntimeError("restart unavailable")

    adapter, lifecycle = FakeAdapter(), AlwaysFailRestart()
    controller = DeceptionController(PersonalityEngine(), DeceptionPlanner(), adapter, lifecycle)
    with pytest.raises(RuntimeError, match="rollback/recovery also failed"):
        controller.apply_for_risk(make_assessment())
    assert adapter.applied_plan is None
    assert lifecycle.restart_calls == 2


def test_cowrie_adapter_preserves_existing_settings_and_comments(tmp_path):
    config_path = tmp_path / "cowrie.cfg"
    config_path.write_text(
        "# Keep this operator comment\n[honeypot]\nhostname = old-host\n"
        "sensor_name = sensor-a\n\n[output_jsonlog]\nenabled = true\n"
        "logfile = var/log/cowrie/cowrie.json\n",
        encoding="utf-8",
    )
    adapter = CowrieAdapter(str(config_path))
    plan = DeceptionPlan("enterprise_database", "db-prod-01", "Ubuntu 22.04", 3)
    adapter.apply(plan)
    updated = config_path.read_text(encoding="utf-8")
    assert "# Keep this operator comment" in updated
    assert "sensor_name = sensor-a" in updated
    assert "[output_jsonlog]" in updated
    assert "enabled = true" in updated
    assert "hostname = db-prod-01" in updated
    config = ConfigParser(interpolation=None)
    config.read(str(config_path), encoding="utf-8")
    assert config.get("shell", "kernel_version") == "5.15.0-91-generic"
    assert config.get("shell", "operating_system") == "GNU/Linux"
    assert config.get("ssh", "version").startswith("SSH-2.0-OpenSSH_8.9p1")


def test_cowrie_adapter_does_not_invent_fingerprint_for_unknown_os(tmp_path):
    config_path = tmp_path / "cowrie.cfg"
    config_path.write_text("[shell]\nkernel_version = operator-defined-version\n", encoding="utf-8")
    adapter = CowrieAdapter(str(config_path))
    plan = DeceptionPlan("custom", "custom-01", "Unknown Linux", 2)
    adapter.apply(plan)
    config = ConfigParser(interpolation=None)
    config.read(str(config_path), encoding="utf-8")
    assert config.get("honeypot", "hostname") == "custom-01"
    assert config.get("shell", "kernel_version") == "operator-defined-version"


def test_cowrie_adapter_rejects_multiline_hostname(tmp_path):
    adapter = CowrieAdapter(str(tmp_path / "cowrie.cfg"))
    plan = DeceptionPlan("invalid", "host\n[ssh]\nversion = injected", "Ubuntu 22.04", 1)
    with pytest.raises(ValueError, match="single-line hostname"):
        adapter.apply(plan)
    assert not (tmp_path / "cowrie.cfg").exists()


def test_cowrie_adapter_current_state_reads_hostname(tmp_path):
    config_path = tmp_path / "cowrie.cfg"
    config_path.write_text("[honeypot]\nhostname = db-prod-01\n", encoding="utf-8")
    state = CowrieAdapter(str(config_path)).current_state()
    assert state.hostname == "db-prod-01"


def test_cowrie_adapter_snapshot_restores_config_and_filesystem(tmp_path):
    config_path = tmp_path / "cowrie.cfg"
    filesystem_path = tmp_path / "morpheus-fs.pickle"
    config_path.write_bytes(b"[honeypot]\nhostname = old-host\n")
    filesystem_path.write_bytes(b"old-filesystem")
    os.chmod(config_path, 0o640)
    os.chmod(filesystem_path, 0o600)
    adapter = CowrieAdapter(
        str(config_path),
        filesystem_base_path=str(tmp_path / "base.pickle"),
        filesystem_output_path=str(filesystem_path),
        filesystem_config_path="/cowrie/etc/morpheus-fs.pickle",
    )
    snapshot = adapter.snapshot_state()
    config_path.write_bytes(b"changed config")
    filesystem_path.write_bytes(b"changed filesystem")
    os.chmod(config_path, 0o644)
    os.chmod(filesystem_path, 0o644)
    adapter.restore_state(snapshot)
    assert config_path.read_bytes() == b"[honeypot]\nhostname = old-host\n"
    assert filesystem_path.read_bytes() == b"old-filesystem"
    assert config_path.stat().st_mode & 0o777 == 0o640
    assert filesystem_path.stat().st_mode & 0o777 == 0o600


def test_cowrie_adapter_snapshot_removes_output_that_did_not_exist(tmp_path):
    config_path = tmp_path / "cowrie.cfg"
    filesystem_path = tmp_path / "morpheus-fs.pickle"
    config_path.write_text("[honeypot]\nhostname = old-host\n", encoding="utf-8")
    adapter = CowrieAdapter(
        str(config_path),
        filesystem_base_path=str(tmp_path / "base.pickle"),
        filesystem_output_path=str(filesystem_path),
        filesystem_config_path="/cowrie/etc/morpheus-fs.pickle",
    )
    snapshot = adapter.snapshot_state()
    filesystem_path.write_bytes(b"new output")
    adapter.restore_state(snapshot)
    assert not filesystem_path.exists()


def test_cowrie_lifecycle_reports_running_container():
    lifecycle = CowrieLifecycle(container_name="morpheus-cowrie")
    assert lifecycle.is_running() is True


def test_cowrie_adapter_separates_ssh_banner_from_shell_ssh_version(tmp_path):
    config_path = tmp_path / "cowrie.cfg"
    config_path.write_text(
        "[honeypot]\nhostname = old-host\n[shell]\nssh_version = old-shell-version\n"
        "[ssh]\nversion = SSH-2.0-old-banner\n",
        encoding="utf-8",
    )
    plan = DeceptionPlan("ubuntu_enterprise", "app-prod-02", "Ubuntu 22.04", 2)
    CowrieAdapter(str(config_path)).apply(plan)
    config = ConfigParser(interpolation=None)
    config.read(str(config_path), encoding="utf-8")
    shell_version = config.get("shell", "ssh_version")
    protocol_version = config.get("ssh", "version")
    assert shell_version.startswith("OpenSSH_8.9p1, OpenSSL")
    assert not shell_version.startswith("SSH-2.0-")
    assert protocol_version.startswith("SSH-2.0-OpenSSH_8.9p1")
    assert shell_version != protocol_version


def test_controller_rejects_production_cowrie_lifecycle():
    lifecycle = CowrieLifecycle(container_name="morpheus-cowrie")

    with pytest.raises(ValueError, match="Production Cowrie lifecycle is blocked"):
        DeceptionController(
            PersonalityEngine(),
            DeceptionPlanner(),
            FakeAdapter(),
            lifecycle,
        )
