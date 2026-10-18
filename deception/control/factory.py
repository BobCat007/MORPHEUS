# Production factory for adaptive Cowrie deception.
from pathlib import Path

from deception.control.controller import DeceptionController
from deception.control.cowrie import CowrieAdapter
from deception.control.cowrie_lifecycle import CowrieLifecycle
from deception.control.planner import DeceptionPlanner
from deception.personality.engine import PersonalityEngine


def create_cowrie_deception_controller(project_root=None, container_name='morpheus-cowrie'):
    root = Path(project_root) if project_root else Path(__file__).resolve().parents[2]
    etc = root / 'deployment' / 'cowrie' / 'etc'
    adapter = CowrieAdapter(
        config_path=str(etc / 'cowrie.cfg'),
        filesystem_base_path=str(etc / 'cowrie-bundled-fs.pickle'),
        filesystem_output_path=str(etc / 'morpheus-fs.pickle'),
        filesystem_config_path='/cowrie/cowrie-git/etc/morpheus-fs.pickle',
    )
    return DeceptionController(
        PersonalityEngine(), DeceptionPlanner(), adapter,
        CowrieLifecycle(container_name=container_name),
    )
