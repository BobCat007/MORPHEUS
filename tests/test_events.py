from core.events.model import MorpheusEvent


def test_event_creation():
    event = MorpheusEvent(
        event_type="authentication_attempt",
        source="test",
        data={
            "username": "admin",
            "success": False,
        },
    )

    result = event.to_dict()

    assert result["event_type"] == "authentication_attempt"
    assert result["source"] == "test"
    assert result["data"]["username"] == "admin"
    assert result["data"]["success"] is False
    assert result["event_id"]
    assert result["timestamp"]
