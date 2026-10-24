import pytest

from core.storage.pipeline_lock import single_instance_by_storage


def test_lock_rejects_second_pipeline_using_same_storage(tmp_path):
    storage_path = tmp_path / "events.jsonl"

    @single_instance_by_storage
    def fake_pipeline(storage_path, attempt_second=False):
        if attempt_second:
            with pytest.raises(
                RuntimeError,
                match="already owns this event store",
            ):
                fake_pipeline(storage_path)
        return "running"

    assert fake_pipeline(storage_path, attempt_second=True) == "running"


def test_lock_is_released_after_pipeline_exits(tmp_path):
    storage_path = tmp_path / "events.jsonl"

    @single_instance_by_storage
    def fake_pipeline(storage_path):
        return "finished"

    assert fake_pipeline(storage_path) == "finished"
    assert fake_pipeline(storage_path) == "finished"


def test_lock_rejects_nested_invocation(tmp_path):
    storage_path = tmp_path / "events.jsonl"

    @single_instance_by_storage
    def fake_pipeline(storage_path, callback=None):
        if callback:
            callback()
        return "running"

    def attempt_second_invocation():
        with pytest.raises(
            RuntimeError,
            match="already owns this event store",
        ):
            fake_pipeline(storage_path)

    assert fake_pipeline(
        storage_path,
        callback=attempt_second_invocation,
    ) == "running"
