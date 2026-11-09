"""Evaluate synthetic command strings against MORPHEUS MITRE mappings."""

from dataclasses import asdict
from datetime import datetime, timezone
from uuid import uuid4

from intelligence.mitre.mapper import MitreMapper
from purple_team.scenarios import SCENARIOS


class PurpleTeamRunner:
    def __init__(self, mapper=None):
        self.mapper = mapper or MitreMapper()

    def list_scenarios(self):
        return [
            {
                "scenario_id": item["scenario_id"],
                "name": item["name"],
                "description": item["description"],
                "tactic": item["tactic"],
                "command_count": len(item["commands"]),
                "expected_techniques": item["expected_techniques"],
            }
            for item in SCENARIOS.values()
        ]

    def run(self, scenario_id):
        scenario = SCENARIOS.get(scenario_id)
        if scenario is None:
            raise KeyError(scenario_id)

        started_at = datetime.now(timezone.utc).isoformat()

        # map_commands parses command strings; it never executes them.
        mapped = self.mapper.map_commands(list(scenario["commands"]))
        detected = [asdict(item) for item in mapped]
        detected_ids = {item["technique_id"] for item in detected}
        expected_ids = list(scenario["expected_techniques"])
        detected_expected = [
            item for item in expected_ids if item in detected_ids
        ]
        missed = [
            item for item in expected_ids if item not in detected_ids
        ]
        coverage = (
            round(len(detected_expected) / len(expected_ids) * 100, 2)
            if expected_ids else 100.0
        )

        return {
            "run_id": str(uuid4()),
            "scenario_id": scenario_id,
            "scenario_name": scenario["name"],
            "status": "completed",
            "source": "purple_team_simulation",
            "started_at": started_at,
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "tactic": scenario["tactic"],
            "command_count": len(scenario["commands"]),
            "simulated_commands": list(scenario["commands"]),
            "expected_techniques": expected_ids,
            "detected_techniques": detected,
            "detected_expected_techniques": detected_expected,
            "missed_techniques": missed,
            "coverage_percent": coverage,
        }
