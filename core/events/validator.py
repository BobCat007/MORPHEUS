from typing import Any, Dict


REQUIRED_FIELDS = {
    "event_id",
    "event_type",
    "source",
    "timestamp",
    "data",
}


def validate_event(event: Dict[str, Any]) -> bool:
    missing_fields = REQUIRED_FIELDS - event.keys()

    if missing_fields:
        raise ValueError(
            f"Event is missing required fields: {sorted(missing_fields)}"
        )

    if not event["event_type"]:
        raise ValueError("event_type cannot be empty")

    if not event["source"]:
        raise ValueError("source cannot be empty")

    if not isinstance(event["data"], dict):
        raise ValueError("data must be a dictionary")

    return True
