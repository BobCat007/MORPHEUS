from deception.control.controller import DeceptionController
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
    def __init__(self):
        self.restart_called = False

    def is_running(self) -> bool:
        return True

    def restart(self) -> None:
        self.restart_called = True


def test_planner_builds_plan_from_personality():
    engine = PersonalityEngine()
    planner = DeceptionPlanner()

    assessment = RiskAssessment(
        session_id="session-1",
        score=70,
        severity="high",
    )

    personality = engine.select(assessment)

    assert personality is not None

    plan = planner.build_plan(personality)

    assert plan.personality_name == "enterprise_database"
    assert plan.hostname == "db-prod-01"
    assert plan.deception_level == 3
    assert "ssh" in plan.services
    assert plan.change_count() == 6


def test_controller_applies_plan_and_restarts_service():
    engine = PersonalityEngine()
    planner = DeceptionPlanner()
    adapter = FakeAdapter()
    lifecycle = FakeLifecycle()

    controller = DeceptionController(
        personality_engine=engine,
        planner=planner,
        adapter=adapter,
        lifecycle=lifecycle,
    )

    assessment = RiskAssessment(
        session_id="session-1",
        score=70,
        severity="high",
    )

    plan = controller.apply_for_risk(assessment)

    assert plan.personality_name == "enterprise_database"
    assert plan.hostname == "db-prod-01"
    assert adapter.applied_plan is plan
    assert lifecycle.restart_called is True


def test_controller_rejects_stopped_deception_service():
    class StoppedLifecycle(FakeLifecycle):
        def is_running(self) -> bool:
            return False

    controller = DeceptionController(
        personality_engine=PersonalityEngine(),
        planner=DeceptionPlanner(),
        adapter=FakeAdapter(),
        lifecycle=StoppedLifecycle(),
    )

    assessment = RiskAssessment(
        session_id="session-1",
        score=70,
        severity="high",
    )

    try:
        controller.apply_for_risk(assessment)
        assert False, "Expected RuntimeError"
    except RuntimeError as exc:
        assert str(exc) == "Deception service is not running."


def test_cowrie_lifecycle_reports_running_container():
    lifecycle = CowrieLifecycle(
        container_name="morpheus-cowrie",
    )

    assert lifecycle.is_running() is True
