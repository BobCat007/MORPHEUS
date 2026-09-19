from typing import Dict, List, Tuple

from intelligence.intent.model import IntentResult


class IntentClassifier:
    """Infer attacker intent from observed commands."""

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

    def classify(self, commands: List[str]) -> List[IntentResult]:
        """Classify attacker intent from a list of commands."""

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
                )
            )

        return results
