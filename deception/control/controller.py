from deception.control.adapter import DeceptionAdapter
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
    ) -> None:
        self.personality_engine = personality_engine
        self.planner = planner
        self.adapter = adapter

    def apply_for_risk(
        self,
        assessment: RiskAssessment,
    ) -> DeceptionPlan:
        """Select and apply the appropriate deception personality."""

        personality = self.personality_engine.select(
            assessment
        )

        if personality is None:
            raise ValueError(
                "No enabled honeypot personality is available."
            )

        plan = self.planner.build_plan(
            personality
        )

        self.adapter.apply(plan)

        return plan

    def current_state(self) -> DeceptionPlan:
        """Return the currently applied deception state."""

        return self.adapter.current_state()
