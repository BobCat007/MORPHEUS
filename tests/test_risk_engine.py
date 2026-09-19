from intelligence.campaign.model import AttackCampaign
from intelligence.fingerprint.model import AttackerFingerprint
from intelligence.intent.model import IntentResult
from intelligence.risk.engine import RiskScoringEngine
from intelligence.session.model import ReconstructedSession
from threat_intel.network.model import NetworkIntelligence


def test_successful_authentication_adds_risk():
    session = ReconstructedSession(
        session_id="session-1",
        username="admin",
        authentication_success=True,
    )

    engine = RiskScoringEngine()
    assessment = engine.assess(session)

    assert assessment.score == 10
    assert assessment.severity == "low"
    assert assessment.factor_count() == 1
    assert assessment.factors[0].name == "successful_authentication"


def test_intent_adds_behavioral_risk():
    session = ReconstructedSession(
        session_id="session-1",
    )

    intents = [
        IntentResult(
            intent="credential_access",
            confidence=0.9,
            evidence=["cat /etc/passwd"],
            phase="credential_access",
        )
    ]

    engine = RiskScoringEngine()
    assessment = engine.assess(
        session=session,
        intents=intents,
    )

    assert assessment.score == 25
    assert assessment.factors[0].name == "intent_credential_access"
    assert "cat /etc/passwd" in assessment.factors[0].evidence


def test_multiple_intents_are_scored():
    session = ReconstructedSession(
        session_id="session-1",
    )

    intents = [
        IntentResult(
            intent="discovery",
            confidence=0.5,
            evidence=["whoami"],
        ),
        IntentResult(
            intent="execution",
            confidence=0.5,
            evidence=["bash"],
        ),
    ]

    engine = RiskScoringEngine()
    assessment = engine.assess(
        session=session,
        intents=intents,
    )

    assert assessment.score == 30
    assert assessment.factor_count() == 2


def test_fingerprint_adds_risk():
    session = ReconstructedSession(
        session_id="session-1",
    )

    fingerprint = AttackerFingerprint(
        fingerprint_id="fingerprint-123",
        session_count=1,
    )

    engine = RiskScoringEngine()
    assessment = engine.assess(
        session=session,
        fingerprint=fingerprint,
    )

    assert assessment.score == 10
    assert assessment.fingerprint_id is None
    assert assessment.factors[0].name == "behavioral_fingerprint"


def test_campaign_adds_risk():
    session = ReconstructedSession(
        session_id="session-1",
    )

    campaign = AttackCampaign(
        campaign_id="campaign-123",
        session_ids=["session-1", "session-2"],
        correlation_reasons=["same_hassh"],
    )

    engine = RiskScoringEngine()
    assessment = engine.assess(
        session=session,
        campaign=campaign,
    )

    assert assessment.score == 15
    assert assessment.campaign_id == "campaign-123"
    assert assessment.factors[0].name == "campaign_correlation"


def test_network_attribution_adds_small_risk_factor():
    session = ReconstructedSession(
        session_id="session-1",
    )

    network = NetworkIntelligence(
        ip_address="8.8.8.8",
        asn="AS15169",
        organization="Google LLC",
        sources=["db-ip"],
    )

    engine = RiskScoringEngine()
    assessment = engine.assess(
        session=session,
        network=network,
    )

    assert assessment.score == 5
    assert assessment.factors[0].name == "network_attribution"
    assert "AS15169" in assessment.factors[0].evidence
    assert "Google LLC" in assessment.factors[0].evidence


def test_network_attribution_does_not_require_reputation():
    session = ReconstructedSession(
        session_id="session-1",
    )

    network = NetworkIntelligence(
        ip_address="8.8.8.8",
        asn="AS15169",
        organization="Google LLC",
    )

    engine = RiskScoringEngine()
    assessment = engine.assess(
        session=session,
        network=network,
    )

    assert assessment.score == 5


def test_complete_assessment_combines_multiple_intelligence_sources():
    session = ReconstructedSession(
        session_id="session-1",
        source_ip="8.8.8.8",
        username="admin",
        authentication_success=True,
    )

    intents = [
        IntentResult(
            intent="credential_access",
            confidence=0.9,
            evidence=["cat /etc/passwd"],
            phase="credential_access",
        ),
        IntentResult(
            intent="execution",
            confidence=0.8,
            evidence=["bash"],
            phase="execution",
        ),
    ]

    fingerprint = AttackerFingerprint(
        fingerprint_id="fingerprint-123",
        session_count=2,
    )

    campaign = AttackCampaign(
        campaign_id="campaign-123",
        session_ids=["session-1", "session-2"],
        correlation_reasons=[
            "same_hassh",
            "shared_commands",
        ],
    )

    network = NetworkIntelligence(
        ip_address="8.8.8.8",
        asn="AS15169",
        organization="Google LLC",
        sources=["db-ip"],
    )

    engine = RiskScoringEngine()

    assessment = engine.assess(
        session=session,
        intents=intents,
        fingerprint=fingerprint,
        campaign=campaign,
        network=network,
    )

    assert assessment.score == 85
    assert assessment.severity == "critical"

    assert assessment.factor_count() == 6
    assert assessment.campaign_id == "campaign-123"

    factor_names = {
        factor.name
        for factor in assessment.factors
    }

    assert factor_names == {
        "successful_authentication",
        "intent_credential_access",
        "intent_execution",
        "behavioral_fingerprint",
        "campaign_correlation",
        "network_attribution",
    }

    assert "network_attribution" in factor_names
