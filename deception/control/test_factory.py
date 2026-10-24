"""Factory restricted to the isolated MORPHEUS test Cowrie deployment."""

import json
import subprocess
from pathlib import Path

from deception.control.controller import DeceptionController
from deception.control.cowrie import CowrieAdapter
from deception.control.cowrie_lifecycle import CowrieLifecycle
from deception.control.planner import DeceptionPlanner
from deception.personality.engine import PersonalityEngine


TEST_CONTAINER = "morpheus-cowrie-test"
TEST_ETC = Path.home() / "morpheus-test" / "etc"
TEST_VAR = Path.home() / "morpheus-test" / "var"
BASELINE = (
    Path(__file__).resolve().parents[2]
    / "deployment" / "cowrie" / "etc" / "cowrie-bundled-fs.pickle"
)


def _validate_test_container() -> None:
    """Fail closed unless Docker confirms the isolated container and mounts."""
    result = subprocess.run(
        ["docker", "inspect", "--format", "{{json .}}", TEST_CONTAINER],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError("Cannot inspect the isolated Cowrie test container.")

    try:
        container = json.loads(result.stdout)
    except (TypeError, json.JSONDecodeError) as exc:
        raise RuntimeError("Docker returned invalid test-container metadata.") from exc

    if (
        container.get("Name") != f"/{TEST_CONTAINER}"
        or container.get("State", {}).get("Running") is not True
    ):
        raise RuntimeError("The isolated Cowrie test container is not running.")

    mounts = {
        mount.get("Destination"): mount.get("Source")
        for mount in container.get("Mounts", [])
    }
    expected = {
        "/cowrie/cowrie-git/etc": str(TEST_ETC.resolve(strict=True)),
        "/cowrie/cowrie-git/var": str(TEST_VAR.resolve(strict=True)),
    }
    for destination, source in expected.items():
        if mounts.get(destination) != source:
            raise RuntimeError(
                f"Unsafe test-container mount for {destination}; refusing activation."
            )


def create_test_cowrie_deception_controller() -> DeceptionController:
    """Construct a controller only after validating isolated paths and mounts."""
    expected = Path.home() / "morpheus-test" / "etc"
    if TEST_ETC != expected or TEST_ETC.is_symlink() or not TEST_ETC.is_dir():
        raise RuntimeError("Test Cowrie configuration directory is unavailable.")

    if TEST_VAR.is_symlink() or not TEST_VAR.is_dir():
        raise RuntimeError("Test Cowrie data directory is unavailable.")

    root = TEST_ETC.resolve(strict=True)
    config_path = root / "cowrie.cfg"
    output_path = root / "morpheus-fs.pickle"

    for path in (config_path, output_path):
        if path.is_symlink() or not path.is_file():
            raise RuntimeError(f"Unsafe or missing test file: {path}")
        if path.resolve(strict=True).parent != root:
            raise RuntimeError(f"Test file escapes the test directory: {path}")

    if BASELINE.is_symlink() or not BASELINE.is_file():
        raise RuntimeError(f"Read-only baseline is unavailable: {BASELINE}")

    baseline_path = BASELINE.resolve(strict=True)
    if baseline_path == output_path.resolve(strict=True):
        raise RuntimeError("Baseline and writable test filesystem must be different.")

    _validate_test_container()

    adapter = CowrieAdapter(
        config_path=str(config_path),
        filesystem_base_path=str(baseline_path),
        filesystem_output_path=str(output_path),
        filesystem_config_path="/cowrie/cowrie-git/etc/morpheus-fs.pickle",
    )
    return DeceptionController(
        PersonalityEngine(),
        DeceptionPlanner(),
        adapter,
        CowrieLifecycle(container_name=TEST_CONTAINER),
    )
