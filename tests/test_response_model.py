from intelligence.response.model import ResponseAction, ResponsePolicy


def test_response_action_stores_basic_information():
    action = ResponseAction(
        name="increase_deception",
        category="deception",
        description="Increase deception level for the attacker.",
        priority=10,
    )

    assert action.name == "increase_deception"
    assert action.category == "deception"
    assert action.description == (
        "Increase deception level for the attacker."
    )
    assert action.priority == 10
    assert action.enabled is True
    assert action.parameters == []


def test_response_action_adds_unique_parameters():
    action = ResponseAction(
        name="expose_fake_asset",
        category="deception",
        description="Expose a fake enterprise asset.",
    )

    action.add_parameter("asset_type")
    action.add_parameter("asset_type")
    action.add_parameter("hostname")

    assert action.parameters == [
        "asset_type",
        "hostname",
    ]


def test_empty_parameter_is_not_added():
    action = ResponseAction(
        name="observe",
        category="monitoring",
        description="Continue observing the attacker.",
    )

    action.add_parameter("")
    action.add_parameter("")

    assert action.parameters == []


def test_response_action_can_be_disabled():
    action = ResponseAction(
        name="isolate_session",
        category="containment",
        description="Isolate the attacker session.",
        enabled=False,
    )

    assert action.enabled is False


def test_response_policy_stores_basic_information():
    policy = ResponsePolicy(
        name="high_risk_policy",
        minimum_severity="high",
        description="Response policy for high-risk attackers.",
    )

    assert policy.name == "high_risk_policy"
    assert policy.minimum_severity == "high"
    assert policy.description == (
        "Response policy for high-risk attackers."
    )
    assert policy.enabled is True
    assert policy.actions == []
    assert policy.action_count() == 0


def test_response_policy_adds_actions():
    policy = ResponsePolicy(
        name="critical_policy",
        minimum_severity="critical",
    )

    action = ResponseAction(
        name="trigger_alert",
        category="alerting",
        description="Trigger a security alert.",
    )

    policy.add_action(action)

    assert policy.action_count() == 1
    assert policy.actions[0] == action


def test_response_policy_does_not_add_duplicate_action():
    policy = ResponsePolicy(
        name="critical_policy",
        minimum_severity="critical",
    )

    action = ResponseAction(
        name="trigger_alert",
        category="alerting",
        description="Trigger a security alert.",
    )

    policy.add_action(action)
    policy.add_action(action)

    assert policy.action_count() == 1


def test_response_policy_can_be_disabled():
    policy = ResponsePolicy(
        name="disabled_policy",
        minimum_severity="high",
        enabled=False,
    )

    assert policy.enabled is False
