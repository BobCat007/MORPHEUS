from intelligence.response.engine import AdaptiveResponseEngine
from intelligence.risk.model import RiskAssessment


def test_low_risk_returns_observation():
    engine = AdaptiveResponseEngine()

    assessment = RiskAssessment(
        session_id="session-1",
        score=10,
        severity="low",
    )

    actions = engine.evaluate(assessment)

    assert [action.name for action in actions] == [
        "observe",
    ]


def test_medium_risk_returns_medium_and_low_actions():
    engine = AdaptiveResponseEngine()

    assessment = RiskAssessment(
        session_id="session-1",
        score=45,
        severity="medium",
    )

    actions = engine.evaluate(assessment)

    action_names = {
        action.name
        for action in actions
    }

    assert action_names == {
        "observe",
        "increase_logging",
        "increase_deception",
    }


def test_high_risk_returns_high_medium_and_low_actions():
    engine = AdaptiveResponseEngine()

    assessment = RiskAssessment(
        session_id="session-1",
        score=70,
        severity="high",
    )

    actions = engine.evaluate(assessment)

    action_names = {
        action.name
        for action in actions
    }

    assert action_names == {
        "observe",
        "increase_logging",
        "increase_deception",
        "expose_fake_asset",
        "capture_payload",
    }


def test_critical_risk_returns_all_response_actions():
    engine = AdaptiveResponseEngine()

    assessment = RiskAssessment(
        session_id="session-1",
        score=90,
        severity="critical",
    )

    actions = engine.evaluate(assessment)

    action_names = {
        action.name
        for action in actions
    }

    assert action_names == {
        "observe",
        "increase_logging",
        "increase_deception",
        "expose_fake_asset",
        "capture_payload",
        "trigger_alert",
        "incident_capture",
    }


def test_actions_are_sorted_by_priority():
    engine = AdaptiveResponseEngine()

    assessment = RiskAssessment(
        session_id="session-1",
        score=90,
        severity="critical",
    )

    actions = engine.evaluate(assessment)

    priorities = [
        action.priority
        for action in actions
    ]

    assert priorities == sorted(
        priorities,
        reverse=True,
    )


def test_disabled_policy_is_ignored():
    engine = AdaptiveResponseEngine()

    engine.policies[1].enabled = False

    assessment = RiskAssessment(
        session_id="session-1",
        score=50,
        severity="medium",
    )

    actions = engine.evaluate(assessment)

    action_names = {
        action.name
        for action in actions
    }

    assert action_names == {
        "observe",
    }


def test_disabled_action_is_ignored():
    engine = AdaptiveResponseEngine()

    engine.policies[1].actions[0].enabled = False

    assessment = RiskAssessment(
        session_id="session-1",
        score=50,
        severity="medium",
    )

    actions = engine.evaluate(assessment)

    action_names = {
        action.name
        for action in actions
    }

    assert action_names == {
        "observe",
        "increase_deception",
    }


def test_custom_policy_can_be_added():
    engine = AdaptiveResponseEngine()

    custom_policy = engine.policies[0].__class__(
        name="custom_policy",
        minimum_severity="low",
    )

    from intelligence.response.model import ResponseAction

    custom_policy.add_action(
        ResponseAction(
            name="custom_action",
            category="custom",
            description="Custom MORPHEUS response.",
            priority=100,
        )
    )

    engine.add_policy(custom_policy)

    assessment = RiskAssessment(
        session_id="session-1",
        score=10,
        severity="low",
    )

    actions = engine.evaluate(assessment)

    assert actions[0].name == "custom_action"
    assert "observe" in {
        action.name
        for action in actions
    }


def test_invalid_severity_does_not_match_policy():
    engine = AdaptiveResponseEngine()

    assessment = RiskAssessment(
        session_id="session-1",
        score=0,
        severity="unknown",
    )

    actions = engine.evaluate(assessment)

    assert actions == []
