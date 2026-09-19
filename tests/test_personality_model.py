from deception.personality.model import HoneypotPersonality


def test_personality_stores_basic_information():
    personality = HoneypotPersonality(
        name="ubuntu_server",
        hostname="app-prod-01",
        operating_system="Ubuntu 22.04",
        deception_level=3,
        description="Ubuntu production application server.",
    )

    assert personality.name == "ubuntu_server"
    assert personality.hostname == "app-prod-01"
    assert personality.operating_system == "Ubuntu 22.04"
    assert personality.deception_level == 3
    assert personality.description == (
        "Ubuntu production application server."
    )
    assert personality.enabled is True


def test_personality_defaults():
    personality = HoneypotPersonality(
        name="default",
        hostname="morpheus-host",
        operating_system="Linux",
    )

    assert personality.deception_level == 1
    assert personality.users == []
    assert personality.services == []
    assert personality.fake_assets == []
    assert personality.response_delay_ms == 0
    assert personality.enabled is True


def test_personality_adds_unique_users():
    personality = HoneypotPersonality(
        name="test",
        hostname="test-host",
        operating_system="Linux",
    )

    personality.add_user("ubuntu")
    personality.add_user("ubuntu")
    personality.add_user("admin")

    assert personality.users == [
        "ubuntu",
        "admin",
    ]


def test_personality_adds_unique_services():
    personality = HoneypotPersonality(
        name="test",
        hostname="test-host",
        operating_system="Linux",
    )

    personality.add_service("ssh")
    personality.add_service("ssh")
    personality.add_service("nginx")

    assert personality.services == [
        "ssh",
        "nginx",
    ]


def test_personality_adds_unique_fake_assets():
    personality = HoneypotPersonality(
        name="test",
        hostname="test-host",
        operating_system="Linux",
    )

    personality.add_fake_asset("/var/backups/db.sql")
    personality.add_fake_asset("/var/backups/db.sql")
    personality.add_fake_asset("/opt/app/config.yaml")

    assert personality.fake_assets == [
        "/var/backups/db.sql",
        "/opt/app/config.yaml",
    ]


def test_empty_values_are_not_added():
    personality = HoneypotPersonality(
        name="test",
        hostname="test-host",
        operating_system="Linux",
    )

    personality.add_user("")
    personality.add_service("")
    personality.add_fake_asset("")

    assert personality.users == []
    assert personality.services == []
    assert personality.fake_assets == []


def test_personality_counts_users_services_and_assets():
    personality = HoneypotPersonality(
        name="test",
        hostname="test-host",
        operating_system="Linux",
    )

    personality.add_user("ubuntu")
    personality.add_user("deploy")

    personality.add_service("ssh")
    personality.add_service("nginx")

    personality.add_fake_asset("/backup/db.sql")

    assert personality.user_count() == 2
    assert personality.service_count() == 2
    assert personality.asset_count() == 1


def test_personality_can_be_disabled():
    personality = HoneypotPersonality(
        name="test",
        hostname="test-host",
        operating_system="Linux",
        enabled=False,
    )

    assert personality.enabled is False


def test_personality_supports_response_delay():
    personality = HoneypotPersonality(
        name="slow_server",
        hostname="legacy-server",
        operating_system="Linux",
        response_delay_ms=750,
    )

    assert personality.response_delay_ms == 750
