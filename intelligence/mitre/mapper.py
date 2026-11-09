import shlex
from typing import Dict, List, Optional

from intelligence.mitre.model import MitreTechnique


class MitreMapper:
    """Map observed commands to MITRE ATT&CK techniques."""

    READ_COMMANDS = {
        "cat", "less", "more", "head", "tail",
        "grep", "sed", "awk",
    }

    TECHNIQUES: Dict[str, Dict[str, str]] = {
        "T1033": {
            "technique_name": "System Owner/User Discovery",
            "tactic": "Discovery",
        },
        "T1082": {
            "technique_name": "System Information Discovery",
            "tactic": "Discovery",
        },
        "T1016": {
            "technique_name": "System Network Configuration Discovery",
            "tactic": "Discovery",
        },
        "T1083": {
            "technique_name": "File and Directory Discovery",
            "tactic": "Discovery",
        },
        "T1087.001": {
            "technique_name": "Account Discovery: Local Account",
            "tactic": "Discovery",
        },
        "T1105": {
            "technique_name": "Ingress Tool Transfer",
            "tactic": "Command and Control",
        },
        "T1222.001": {
            "technique_name": "File and Directory Permissions Modification",
            "tactic": "Defense Evasion",
        },
        "T1070.003": {
            "technique_name": "Clear Command History",
            "tactic": "Defense Evasion",
        },
        "T1003.008": {
            "technique_name": "OS Credential Dumping: /etc/passwd and /etc/shadow",
            "tactic": "Credential Access",
        },
        "T1552.001": {
            "technique_name": "Unsecured Credentials: Credentials In Files",
            "tactic": "Credential Access",
        },
    }

    def _parse(self, command: str) -> List[str]:
        try:
            return shlex.split(command)
        except ValueError:
            return command.strip().split()

    def _identify(self, command: str) -> Optional[str]:
        tokens = self._parse(command)
        if not tokens:
            return None

        # Handle common command wrappers.
        while tokens and tokens[0] in {"sudo", "command"}:
            tokens.pop(0)

        if not tokens:
            return None

        executable = tokens[0].rsplit("/", 1)[-1].lower()
        args = [token.lower() for token in tokens[1:]]
        normalized = command.lower()

        # Specific credential paths take priority over generic commands.
        if executable in self.READ_COMMANDS:
            if any("/etc/shadow" in token for token in args):
                return "T1003.008"

            if any("/etc/passwd" in token for token in args):
                return "T1087.001"

            if any(
                path in normalized
                for path in (
                    "/opt/company/secrets.env",
                    "/home/backup/credentials.txt",
                )
            ):
                return "T1552.001"

        if executable in {"whoami", "id"}:
            return "T1033"

        if executable in {"uname", "hostname"}:
            return "T1082"

        if executable == "ifconfig":
            return "T1016"

        if executable == "ip" and args:
            if args[0] in {"addr", "address", "a", "route", "r"}:
                return "T1016"

        if executable in {"ls", "pwd", "find", "locate", "tree"}:
            return "T1083"

        if executable == "wget":
            return "T1105" if args else None

        if executable == "curl":
            has_url = any(
                token.startswith(("http://", "https://", "ftp://"))
                for token in args
            )
            has_output = any(
                token in {"-o", "-O", "--output"}
                or token.startswith("--output=")
                for token in args
            )
            return "T1105" if has_url or has_output else None

        if executable == "chmod":
            return "T1222.001"

        if executable == "history" and "-c" in args:
            return "T1070.003"

        return None

    def map_commands(self, commands: List[str]) -> List[MitreTechnique]:
        """Map commands to ATT&CK techniques and group supporting evidence."""

        techniques: Dict[str, MitreTechnique] = {}

        for command in commands:
            if not isinstance(command, str) or not command.strip():
                continue

            technique_id = self._identify(command)
            if technique_id is None:
                continue

            mapping = self.TECHNIQUES[technique_id]

            if technique_id not in techniques:
                techniques[technique_id] = MitreTechnique(
                    technique_id=technique_id,
                    technique_name=mapping["technique_name"],
                    tactic=mapping["tactic"],
                )

            techniques[technique_id].add_evidence(command)

        return list(techniques.values())
