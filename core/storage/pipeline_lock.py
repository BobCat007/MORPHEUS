"""Prevent multiple live pipelines from using the same event store."""

import fcntl
import inspect
from functools import wraps
from pathlib import Path


def single_instance_by_storage(function):
    """Allow only one running invocation per resolved storage path."""

    signature = inspect.signature(function)

    @wraps(function)
    def wrapper(*args, **kwargs):
        bound = signature.bind(*args, **kwargs)
        bound.apply_defaults()

        storage_path = Path(bound.arguments["storage_path"]).expanduser().resolve()
        storage_path.parent.mkdir(parents=True, exist_ok=True)

        lock_path = storage_path.with_name(storage_path.name + ".pipeline.lock")

        with lock_path.open("a+") as lock_file:
            try:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise RuntimeError(
                    "Another live MORPHEUS pipeline already owns this event "
                    f"store: {storage_path}. Stop the other pipeline before "
                    "starting another one."
                ) from exc

            try:
                return function(*args, **kwargs)
            finally:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)

    return wrapper
