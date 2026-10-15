from configparser import ConfigParser

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

    def apply(self, plan: DeceptionPlan) -> None:
        self.applied_plan = plan

    def current_state(self) -> DeceptionPlan:
        if self.applied_plan is None:
            raise ValueError("No plan has been applied.")
        return self.applied_plan


class FakeLifecycle:
    def __init__(self, running=True):
        self.running = running
        self.restart_called = False

    def is_running(self) -> bool:
        return self.running

    def restart(self) -> None:
        self.restart_called = True


def make_assessment(severity="high", score=70):
    return RiskAssessment(
        session_id="session-1",
        score=score,
        severity=severity,
    )


def test_planner_builds_plan_from_personality():
    engine = PersonalityEngine()
    plan = DeceptionPlanner().build_plan(
        engine.select(make_assessment())
    )

    assert plan.personality_name == "enterprise_database"
    assert plan.hostname == "db-prod-01"
    assert plan.deception_level == 3
    assert "ssh" in plan.services
    assert plan.change_count() == 6


def test_controller_applies_plan_and_restarts_service():
    adapter = FakeAdapter()
    lifecycle = FakeLifecycle()
    controller = DeceptionController(
        PersonalityEngine(), DeceptionPlanner(), adapter, lifecycle
    )

    plan = controller.apply_for_risk(make_assessment())

    assert plan.personality_name == "enterprise_database"
    assert adapter.applied_plan is plan
    assert lifecycle.restart_called is True


def test_controller_checks_service_before_applying_plan():
    adapter = FakeAdapter()
    lifecycle = FakeLifecycle(running=False)
    controller = DeceptionController(
        PersonalityEngine(), DeceptionPlanner(), adapter, lifecycle
    )

    with pytest.raises(
        RuntimeError, match="Deception service is not running"
    ):
        controller.apply_for_risk(make_assessment())

    assert adapter.applied_plan is None
    assert lifecycle.restart_called is False


def test_controller_does_not_restart_if_adapter_fails():
    class BrokenAdapter(FakeAdapter):
        def apply(self, plan):
            raise OSError("configuration write failed")

    lifecycle = FakeLifecycle()
    controller = DeceptionController(
        PersonalityEngine(), DeceptionPlanner(),
        BrokenAdapter(), lifecycle
    )

    with pytest.raises(OSError, match="configuration write failed"):
        controller.apply_for_risk(make_assessment())

    assert lifecycle.restart_called is False


def test_cowrie_adapter_preserves_existing_settings_and_comments(tmp_path):
    config_path = tmp_path / "cowrie.cfg"
    config_path.write_text(
        "# Keep this operator comment\n"
        "[honeypot]\n"
        "hostname = old-host\n"
        "sensor_name = sensor-a\n"
        "\n"
        "[output_jsonlog]\n"
        "enabled = true\n"
        "logfile = var/log/cowrie/cowrie.json\n",
        encoding="utf-8",
    )
    adapter = CowrieAdapter(str(config_path))
    plan = DeceptionPlan(
        personality_name="enterprise_database",
        hostname="db-prod-01",
        operating_system="Ubuntu 22.04",
        deception_level=3,
    )

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
    config_path.write_text(
        "[shell]\n"
        "kernel_version = operator-defined-version\n",
        encoding="utf-8",
    )
    adapter = CowrieAdapter(str(config_path))
    plan = DeceptionPlan(
        personality_name="custom",
        hostname="custom-01",
        operating_system="Unknown Linux",
        deception_level=2,
    )

    adapter.apply(plan)

    config = ConfigParser(interpolation=None)
    config.read(str(config_path), encoding="utf-8")
    assert config.get("honeypot", "hostname") == "custom-01"
    assert config.get("shell", "kernel_version") == "operator-defined-version"


def test_cowrie_adapter_rejects_multiline_hostname(tmp_path):
    adapter = CowrieAdapter(str(tmp_path / "cowrie.cfg"))
    plan = DeceptionPlan(
        personality_name="invalid",
        hostname="host\n[ssh]\nversion = injected",
        operating_system="Ubuntu 22.04",
        deception_level=1,
    )

    with pytest.raises(ValueError, match="single-line hostname"):
        adapter.apply(plan)

    assert not (tmp_path / "cowrie.cfg").exists()


def test_cowrie_adapter_current_state_reads_hostname(tmp_path):
    config_path = tmp_path / "cowrie.cfg"
    config_path.write_text(
        "[honeypot]\nhostname = db-prod-01\n",
        encoding="utf-8",
    )

    state = CowrieAdapter(str(config_path)).current_state()

    assert state.hostname == "db-prod-01"


def test_cowrie_lifecycle_reports_running_container():
    lifecycle = CowrieLifecycle(container_name="morpheus-cowrie")
    assert lifecycle.is_running() is True


def test_cowrie_adapter_separates_ssh_banner_from_shell_ssh_version(
    tmp_path,
):
    config_path = tmp_path / "cowrie.cfg"
    config_path.write_text(
        "[honeypot]\nhostname = old-host\n"
        "[shell]\nssh_version = old-shell-version\n"
        "[ssh]\nversion = SSH-2.0-old-banner\n",
        encoding="utf-8",
    )

    plan = DeceptionPlan(
        personality_name="ubuntu_enterprise",
        hostname="app-prod-02",
        operating_system="Ubuntu 22.04",
        deception_level=2,
    )
    CowrieAdapter(str(config_path)).apply(plan)

    config = ConfigParser(interpolation=None)
    config.read(str(config_path), encoding="utf-8")

    shell_version = config.get("shell", "ssh_version")
    protocol_version = config.get("ssh", "version")

    assert shell_version.startswith("OpenSSH_8.9p1, OpenSSL")
    assert not shell_version.startswith("SSH-2.0-")
    assert protocol_version.startswith("SSH-2.0-OpenSSH_8.9p1")
    assert shell_version != protocol_version
