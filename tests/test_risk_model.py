from intelligence.risk.model import RiskAssessment, RiskFactor


def test_risk_factor_stores_basic_information():
    factor = RiskFactor(
        name="credential_access",
        score=20,
        category="behavior",
        evidence=["cat /etc/passwd"],
    )

    assert factor.name == "credential_access"
    assert factor.score == 20
    assert factor.category == "behavior"
    assert factor.evidence == ["cat /etc/passwd"]


def test_risk_factor_adds_unique_evidence():
    factor = RiskFactor(
        name="discovery",
        score=10,
        category="behavior",
    )

    factor.add_evidence("whoami")
    factor.add_evidence("whoami")
    factor.add_evidence("uname -a")

    assert factor.evidence == [
        "whoami",
        "uname -a",
    ]


def test_risk_assessment_calculates_score():
    assessment = RiskAssessment(
        session_id="session-123",
    )

    assessment.add_factor(
        RiskFactor(
            name="discovery",
            score=15,
            category="behavior",
        )
    )

    assessment.add_factor(
        RiskFactor(
            name="credential_access",
            score=25,
            category="behavior",
        )
    )

    assert assessment.calculate_score() == 40
    assert assessment.score == 40


def test_risk_score_is_capped_at_100():
    assessment = RiskAssessment(
        session_id="session-123",
    )

    assessment.add_factor(
        RiskFactor(
            name="factor_one",
            score=80,
            category="test",
        )
    )

    assessment.add_factor(
        RiskFactor(
            name="factor_two",
            score=50,
            category="test",
        )
    )

    assert assessment.calculate_score() == 100


def test_risk_score_cannot_be_negative():
    assessment = RiskAssessment(
        session_id="session-123",
    )

    assessment.add_factor(
        RiskFactor(
            name="negative_factor",
            score=-50,
            category="test",
        )
    )

    assert assessment.calculate_score() == 0


def test_severity_is_low_for_low_score():
    assessment = RiskAssessment(
        session_id="session-123",
        score=20,
    )

    assert assessment.calculate_severity() == "low"


def test_severity_is_medium_for_medium_score():
    assessment = RiskAssessment(
        session_id="session-123",
        score=45,
    )

    assert assessment.calculate_severity() == "medium"


def test_severity_is_high_for_high_score():
    assessment = RiskAssessment(
        session_id="session-123",
        score=70,
    )

    assert assessment.calculate_severity() == "high"


def test_severity_is_critical_for_critical_score():
    assessment = RiskAssessment(
        session_id="session-123",
        score=90,
    )

    assert assessment.calculate_severity() == "critical"


def test_finalize_calculates_score_and_severity():
    assessment = RiskAssessment(
        session_id="session-123",
    )

    assessment.add_factor(
        RiskFactor(
            name="discovery",
            score=20,
            category="behavior",
        )
    )

    assessment.add_factor(
        RiskFactor(
            name="credential_access",
            score=50,
            category="behavior",
        )
    )

    assessment.finalize()

    assert assessment.score == 70
    assert assessment.severity == "high"


def test_factor_count():
    assessment = RiskAssessment(
        session_id="session-123",
    )

    assessment.add_factor(
        RiskFactor(
            name="discovery",
            score=15,
            category="behavior",
        )
    )

    assessment.add_factor(
        RiskFactor(
            name="execution",
            score=30,
            category="behavior",
        )
    )

    assert assessment.factor_count() == 2
