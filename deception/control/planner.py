from deception.control.model import DeceptionChange, DeceptionPlan
from deception.personality.model import HoneypotPersonality


class DeceptionPlanner:
    """Convert a honeypot personality into an executable deception plan."""

    def build_plan(
        self,
        personality: HoneypotPersonality,
    ) -> DeceptionPlan:
        """Build a deception plan from the selected personality."""

        plan = DeceptionPlan(
            personality_name=personality.name,
            hostname=personality.hostname,
            operating_system=personality.operating_system,
            deception_level=personality.deception_level,
            users=list(personality.users),
            services=list(personality.services),
            fake_assets=list(personality.fake_assets),
            response_delay_ms=personality.response_delay_ms,
        )

        plan.add_change(
            DeceptionChange(
                name="hostname",
                category="identity",
                value=personality.hostname,
                reason="Apply selected honeypot personality.",
            )
        )

        plan.add_change(
            DeceptionChange(
                name="operating_system",
                category="identity",
                value=personality.operating_system,
                reason="Present the selected operating system identity.",
            )
        )

        plan.add_change(
            DeceptionChange(
                name="users",
                category="identity",
                value=",".join(personality.users),
                reason="Present the selected fake user set.",
            )
        )

        plan.add_change(
            DeceptionChange(
                name="services",
                category="services",
                value=",".join(personality.services),
                reason="Present the selected service profile.",
            )
        )

        plan.add_change(
            DeceptionChange(
                name="fake_assets",
                category="assets",
                value=",".join(personality.fake_assets),
                reason="Present the selected fake enterprise assets.",
            )
        )

        plan.add_change(
            DeceptionChange(
                name="response_delay_ms",
                category="behavior",
                value=str(personality.response_delay_ms),
                reason="Apply the selected human-like response delay.",
            )
        )

        return plan
