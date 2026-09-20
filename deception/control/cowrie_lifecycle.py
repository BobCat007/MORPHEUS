import subprocess

from deception.control.lifecycle import DeceptionLifecycle


class CowrieLifecycle(DeceptionLifecycle):
    """Manage the Docker lifecycle of the MORPHEUS Cowrie container."""

    def __init__(self, container_name: str = "morpheus-cowrie") -> None:
        self.container_name = container_name

    def restart(self) -> None:
        """Restart the Cowrie Docker container."""

        result = subprocess.run(
            ["docker", "restart", self.container_name],
            capture_output=True,
            text=True,
            check=False,
        )

        if result.returncode != 0:
            raise RuntimeError(
                f"Failed to restart Cowrie: {result.stderr.strip()}"
            )

    def is_running(self) -> bool:
        """Return whether the Cowrie container is currently running."""

        result = subprocess.run(
            [
                "docker",
                "inspect",
                "-f",
                "{{.State.Running}}",
                self.container_name,
            ],
            capture_output=True,
            text=True,
            check=False,
        )

        if result.returncode != 0:
            return False

        return result.stdout.strip().lower() == "true"
