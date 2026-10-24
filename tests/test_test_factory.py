import json
import subprocess
from pathlib import Path

import pytest

from deception.control import test_factory


def docker_inspect_result(*, running=True, wrong_mount=False):
    root = Path.home() / "morpheus-test"
    mounts = [
        {
            "Source": str(root / "etc"),
            "Destination": "/cowrie/cowrie-git/etc",
        },
        {
            "Source": str(root / ("wrong-var" if wrong_mount else "var")),
            "Destination": "/cowrie/cowrie-git/var",
        },
    ]
    return subprocess.CompletedProcess(
        args=["docker", "inspect"],
        returncode=0,
        stdout=json.dumps({
            "Name": "/morpheus-cowrie-test",
            "State": {"Running": running},
            "Mounts": mounts,
        }),
        stderr="",
    )


def test_test_factory_targets_isolated_container(monkeypatch):
    captured = {}

    class FakeAdapter:
        def __init__(self, **kwargs):
            captured["adapter"] = kwargs

    class FakeLifecycle:
        def __init__(self, container_name):
            captured["container_name"] = container_name

    class FakeController:
        def __init__(self, personality, planner, adapter, lifecycle):
            captured["controller"] = True

    monkeypatch.setattr(test_factory, "CowrieAdapter", FakeAdapter)
    monkeypatch.setattr(test_factory, "CowrieLifecycle", FakeLifecycle)
    monkeypatch.setattr(test_factory, "DeceptionController", FakeController)
    monkeypatch.setattr(
        test_factory.subprocess,
        "run",
        lambda *a, **k: docker_inspect_result(),
    )

    test_factory.create_test_cowrie_deception_controller()

    args = captured["adapter"]
    assert captured["container_name"] == "morpheus-cowrie-test"
    assert args["config_path"] == str(
        (Path.home() / "morpheus-test/etc/cowrie.cfg").resolve()
    )
    assert args["filesystem_output_path"] == str(
        (Path.home() / "morpheus-test/etc/morpheus-fs.pickle").resolve()
    )
    assert args["filesystem_base_path"] == str(test_factory.BASELINE.resolve())
    assert args["filesystem_base_path"] != args["filesystem_output_path"]
    assert "/deployment/cowrie/" not in args["config_path"]


def test_test_factory_rejects_unexpected_directory(monkeypatch, tmp_path):
    monkeypatch.setattr(test_factory, "TEST_ETC", tmp_path)
    with pytest.raises(RuntimeError, match="configuration directory"):
        test_factory.create_test_cowrie_deception_controller()


def test_test_factory_rejects_wrong_container_mounts(monkeypatch):
    monkeypatch.setattr(
        test_factory.subprocess,
        "run",
        lambda *a, **k: docker_inspect_result(wrong_mount=True),
    )
    with pytest.raises(RuntimeError, match="Unsafe test-container mount"):
        test_factory._validate_test_container()


def test_test_factory_rejects_stopped_container(monkeypatch):
    monkeypatch.setattr(
        test_factory.subprocess,
        "run",
        lambda *a, **k: docker_inspect_result(running=False),
    )
    with pytest.raises(RuntimeError, match="not running"):
        test_factory._validate_test_container()


def test_test_factory_rejects_docker_inspect_failure(monkeypatch):
    monkeypatch.setattr(
        test_factory.subprocess,
        "run",
        lambda *a, **k: subprocess.CompletedProcess(
            args=["docker", "inspect"], returncode=1, stdout="", stderr="missing"
        ),
    )
    with pytest.raises(RuntimeError, match="Cannot inspect"):
        test_factory._validate_test_container()
