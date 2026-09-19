from deception.personality.engine import PersonalityEngine
from deception.personality.model import HoneypotPersonality
from intelligence.risk.model import RiskAssessment


def test_low_risk_selects_normal_personality():
    engine = PersonalityEngine()

    assessment = RiskAssessment(
        session_id="session-1",
        score=10,
        severity="low",
    )

    personality = engine.select(assessment)

    assert personality is not None
    assert personality.name == "ubuntu_server"
    assert personality.deception_level == 1


def test_medium_risk_selects_enterprise_personality():
    engine = PersonalityEngine()

    assessment = RiskAssessment(
        session_id="session-1",
        score=45,
        severity="medium",
    )

    personality = engine.select(assessment)

    assert personality is not None
    assert personality.name == "ubuntu_enterprise"
    assert personality.deception_level == 2


def test_high_risk_selects_database_personality():
    engine = PersonalityEngine()

    assessment = RiskAssessment(
        session_id="session-1",
        score=70,
        severity="high",
    )

    personality = engine.select(assessment)

    assert personality is not None
    assert personality.name == "enterprise_database"
    assert personality.deception_level == 3


def test_critical_risk_selects_deep_enterprise_personality():
    engine = PersonalityEngine()

    assessment = RiskAssessment(
        session_id="session-1",
        score=90,
        severity="critical",
    )

    personality = engine.select(assessment)

    assert personality is not None
    assert personality.name == "enterprise_internal"
    assert personality.deception_level == 4


def test_selected_personality_is_enabled():
    engine = PersonalityEngine()

    assessment = RiskAssessment(
        session_id="session-1",
        score=70,
        severity="high",
    )

    personality = engine.select(assessment)

    assert personality is not None
    assert personality.enabled is True


def test_disabled_personality_is_not_selected():
    engine = PersonalityEngine()

    engine.personalities[2].enabled = False

    assessment = RiskAssessment(
        session_id="session-1",
        score=70,
        severity="high",
    )

    personality = engine.select(assessment)

    assert personality is not None
    assert personality.name != "enterprise_database"


def test_no_enabled_personality_returns_none():
    engine = PersonalityEngine()

    for personality in engine.personalities:
        personality.enabled = False

    assessment = RiskAssessment(
        session_id="session-1",
        score=70,
        severity="high",
    )

    assert engine.select(assessment) is None


def test_custom_personality_can_be_added():
    engine = PersonalityEngine()

    custom = HoneypotPersonality(
        name="custom_server",
        hostname="custom-01",
        operating_system="Debian 12",
        deception_level=2,
    )

    engine.add_personality(custom)

    assert custom in engine.personalities


def test_personality_contains_expected_fake_assets():
    engine = PersonalityEngine()

    assessment = RiskAssessment(
        session_id="session-1",
        score=90,
        severity="critical",
    )

    personality = engine.select(assessment)

    assert personality is not None
    assert personality.asset_count() >= 3
    assert "/opt/company/secrets.env" in personality.fake_assets


def test_personality_contains_expected_services():
    engine = PersonalityEngine()

    assessment = RiskAssessment(
        session_id="session-1",
        score=90,
        severity="critical",
    )

    personality = engine.select(assessment)

    assert personality is not None

    assert "ssh" in personality.services
    assert "mysql" in personality.services
    assert "redis" in personality.services
    assert "smb" in personality.services
