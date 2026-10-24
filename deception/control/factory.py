# Production factory for adaptive Cowrie deception.
from pathlib import Path

from deception.control.controller import DeceptionController
from deception.control.cowrie import CowrieAdapter
from deception.control.cowrie_lifecycle import CowrieLifecycle
from deception.control.planner import DeceptionPlanner
from deception.personality.engine import PersonalityEngine


def create_cowrie_deception_controller(project_root=None, container_name=None):
    """Refuse controller creation until an explicitly isolated factory is used."""
    raise RuntimeError(
        "Production factory activation is disabled for safety. "
        "Use create_test_cowrie_deception_controller() with the validated "
        "morpheus-cowrie-test deployment."
    )
