from abc import ABC, abstractmethod


class DeceptionLifecycle(ABC):
    """Manage the runtime lifecycle of a deception service."""

    @abstractmethod
    def restart(self) -> None:
        """Restart the deception service."""
        raise NotImplementedError

    @abstractmethod
    def is_running(self) -> bool:
        """Return whether the deception service is currently running."""
        raise NotImplementedError
