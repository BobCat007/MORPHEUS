from abc import ABC, abstractmethod

from deception.control.model import DeceptionPlan


class DeceptionAdapter(ABC):
    """Interface for applying deception plans to a honeypot backend."""

    @abstractmethod
    def apply(
        self,
        plan: DeceptionPlan,
    ) -> None:
        """Apply a deception plan to the backend."""

        raise NotImplementedError

    @abstractmethod
    def current_state(self) -> DeceptionPlan:
        """Return the currently applied deception state."""

        raise NotImplementedError
