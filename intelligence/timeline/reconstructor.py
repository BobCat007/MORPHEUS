from typing import Dict, List

from intelligence.mitre.mapper import MitreMapper
from intelligence.mitre.model import MitreTechnique
from intelligence.session.model import ReconstructedSession
from intelligence.timeline.model import TimelineEvent


class TimelineReconstructor:
    """Build a chronological attack timeline from a reconstructed session."""

    def __init__(self) -> None:
        self.mitre_mapper = MitreMapper()

    def build(
        self,
        session: ReconstructedSession,
    ) -> List[TimelineEvent]:
        """Build timeline events from a reconstructed session."""

        timeline: List[TimelineEvent] = []

        if session.start_time:
            timeline.append(
                TimelineEvent(
                    timestamp=session.start_time,
                    event_type="session_started",
                    session_id=session.session_id,
                )
            )

        techniques = self.mitre_mapper.map_commands(
            session.commands
        )

        technique_by_command = self._build_command_mapping(
            techniques
        )

        for command_event in session.command_events:
            command = command_event.command
            mapped_technique = technique_by_command.get(command)

            if mapped_technique:
                timeline.append(
                    TimelineEvent(
                        timestamp=command_event.timestamp,
                        event_type="command",
                        session_id=session.session_id,
                        command=command,
                        technique_id=mapped_technique.technique_id,
                        technique_name=mapped_technique.technique_name,
                        tactic=mapped_technique.tactic,
                        evidence=[command],
                    )
                )
            else:
                timeline.append(
                    TimelineEvent(
                        timestamp=command_event.timestamp,
                        event_type="command",
                        session_id=session.session_id,
                        command=command,
                        evidence=[command],
                    )
                )

        if session.end_time:
            timeline.append(
                TimelineEvent(
                    timestamp=session.end_time,
                    event_type="session_ended",
                    session_id=session.session_id,
                )
            )

        return timeline

    def _build_command_mapping(
        self,
        techniques: List[MitreTechnique],
    ) -> Dict[str, MitreTechnique]:
        """Create a command-to-technique lookup."""

        mapping: Dict[str, MitreTechnique] = {}

        for technique in techniques:
            for evidence in technique.evidence:
                mapping[evidence] = technique

        return mapping
