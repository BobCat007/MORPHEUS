from deception.control.adapter import DeceptionAdapter
from deception.control.cowrie_lifecycle import CowrieLifecycle
from deception.control.model import DeceptionPlan
from deception.control.planner import DeceptionPlanner
from deception.personality.engine import PersonalityEngine
from intelligence.risk.model import RiskAssessment


class DeceptionController:
    """Coordinate risk assessment with adaptive deception control."""

    def __init__(
        self,
        personality_engine: PersonalityEngine,
        planner: DeceptionPlanner,
        adapter: DeceptionAdapter,
        lifecycle: CowrieLifecycle,
    ) -> None:
        if (
            isinstance(lifecycle, CowrieLifecycle)
            and lifecycle.container_name == "morpheus-cowrie"
        ):
            raise ValueError(
                "Production Cowrie lifecycle is blocked in the adaptive "
                "deception controller; use the isolated test container."
            )

        self.personality_engine = personality_engine
        self.planner = planner
        self.adapter = adapter
        self.lifecycle = lifecycle
        self._last_applied_plan = None

    def apply_for_risk(
        self,
        assessment: RiskAssessment,
    ) -> DeceptionPlan:
        """Apply a risk-selected plan, attempting rollback on failure."""
        personality = self.personality_engine.select(assessment)
        if personality is None:
            raise ValueError("No enabled honeypot personality is available.")

        # Check service state before touching its configuration.
        if not self.lifecycle.is_running():
            raise RuntimeError("Deception service is not running.")

        plan = self.planner.build_plan(personality)
        if plan == self._last_applied_plan:
            return plan

        snapshot_method = getattr(self.adapter, "snapshot_state", None)
        restore_method = getattr(self.adapter, "restore_state", None)
        snapshot = (
            snapshot_method()
            if callable(snapshot_method) and callable(restore_method)
            else None
        )

        apply_completed = False
        try:
            self.adapter.apply(plan)
            apply_completed = True
            self.lifecycle.restart()
        except Exception as operation_error:
            if snapshot is not None and callable(restore_method):
                try:
                    restore_method(snapshot)
                    # If apply failed, restore files without restarting.
                    # If restart failed, attempt recovery with restored files.
                    if apply_completed:
                        self.lifecycle.restart()
                except Exception as rollback_error:
                    raise RuntimeError(
                        "Adaptive deception failed: {}; "
                        "rollback/recovery also failed: {}".format(
                            operation_error, rollback_error
                        )
                    ) from rollback_error
            raise

        self._last_applied_plan = plan
        return plan

    def current_state(self) -> DeceptionPlan:
        """Return the currently applied deception state."""
        return self.adapter.current_state()
