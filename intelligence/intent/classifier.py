from typing import Dict, List, Optional

from intelligence.intent.model import IntentResult
from intelligence.session.model import ReconstructedSession


class IntentClassifier:
    """Infer attacker intent from observed commands and session behavior."""

    COMMAND_RULES: Dict[str, List[str]] = {
        "discovery": [
            "whoami",
            "id",
            "uname",
            "hostname",
            "ifconfig",
            "ip addr",
            "ip route",
            "cat /etc/os-release",
        ],
        "file_discovery": [
            "ls",
            "pwd",
            "find",
            "locate",
            "tree",
        ],
        "payload_retrieval": [
            "wget",
            "curl",
            "ftp",
            "tftp",
        ],
        "execution": [
            "chmod",
            "./",
            "bash",
            "sh ",
            "python",
            "python3",
            "perl",
        ],
        "credential_access": [
            "/etc/passwd",
            "/etc/shadow",
            "history",
            "ssh-key",
        ],
        "defense_evasion": [
            "rm ",
            "history -c",
            "unset history",
            "clear",
        ],
    }

    INTENT_PHASES: Dict[str, str] = {
        "discovery": "reconnaissance",
        "file_discovery": "reconnaissance",
        "payload_retrieval": "delivery",
        "execution": "execution",
        "credential_access": "credential_access",
        "defense_evasion": "defense_evasion",
    }

    def classify(
        self,
        commands: Optional[List[str]] = None,
        session: Optional[ReconstructedSession] = None,
    ) -> List[IntentResult]:
        """Classify attacker intent from commands and optional session data."""

        if session is not None:
            commands = session.commands

        if not commands:
            return []

        scores: Dict[str, int] = {}
        evidence: Dict[str, List[str]] = {}

        for command in commands:
            normalized = command.lower().strip()

            for intent, indicators in self.COMMAND_RULES.items():
                for indicator in indicators:
                    if indicator in normalized:
                        scores[intent] = scores.get(intent, 0) + 1
                        evidence.setdefault(intent, []).append(command)
                        break

        if not scores:
            return []

        total_matches = sum(scores.values())
        results: List[IntentResult] = []

        for intent, score in sorted(
            scores.items(),
            key=lambda item: item[1],
            reverse=True,
        ):
            confidence = score / total_matches

            results.append(
                IntentResult(
                    intent=intent,
                    confidence=round(confidence, 3),
                    evidence=evidence[intent],
                    phase=self.INTENT_PHASES.get(intent),
                )
            )

        return results
