from typing import Dict, List

from intelligence.mitre.model import MitreTechnique


class MitreMapper:
    """Map observed commands to MITRE ATT&CK techniques."""

    COMMAND_RULES: Dict[str, Dict[str, str]] = {
        "whoami": {
            "technique_id": "T1033",
            "technique_name": "System Owner/User Discovery",
            "tactic": "Discovery",
        },
        "id": {
            "technique_id": "T1033",
            "technique_name": "System Owner/User Discovery",
            "tactic": "Discovery",
        },
        "uname": {
            "technique_id": "T1082",
            "technique_name": "System Information Discovery",
            "tactic": "Discovery",
        },
        "hostname": {
            "technique_id": "T1033",
            "technique_name": "System Owner/User Discovery",
            "tactic": "Discovery",
        },
        "ifconfig": {
            "technique_id": "T1016",
            "technique_name": "System Network Configuration Discovery",
            "tactic": "Discovery",
        },
        "ip addr": {
            "technique_id": "T1016",
            "technique_name": "System Network Configuration Discovery",
            "tactic": "Discovery",
        },
        "ip route": {
            "technique_id": "T1016",
            "technique_name": "System Network Configuration Discovery",
            "tactic": "Discovery",
        },
        "ls": {
            "technique_id": "T1083",
            "technique_name": "File and Directory Discovery",
            "tactic": "Discovery",
        },
        "pwd": {
            "technique_id": "T1083",
            "technique_name": "File and Directory Discovery",
            "tactic": "Discovery",
        },
        "find": {
            "technique_id": "T1083",
            "technique_name": "File and Directory Discovery",
            "tactic": "Discovery",
        },
        "wget": {
            "technique_id": "T1105",
            "technique_name": "Ingress Tool Transfer",
            "tactic": "Command and Control",
        },
        "curl": {
            "technique_id": "T1105",
            "technique_name": "Ingress Tool Transfer",
            "tactic": "Command and Control",
        },
        "chmod": {
            "technique_id": "T1222.001",
            "technique_name": "File and Directory Permissions Modification",
            "tactic": "Defense Evasion",
        },
        "history -c": {
            "technique_id": "T1070.003",
            "technique_name": "Clear Command History",
            "tactic": "Defense Evasion",
        },
        "/etc/passwd": {
            "technique_id": "T1003.008",
            "technique_name": "OS Credential Dumping: /etc/passwd and /etc/shadow",
            "tactic": "Credential Access",
        },
    }

    def map_commands(self, commands: List[str]) -> List[MitreTechnique]:
        """Map observed commands to ATT&CK techniques."""

        techniques: Dict[str, MitreTechnique] = {}

        for command in commands:
            normalized = command.lower().strip()

            for indicator, mapping in self.COMMAND_RULES.items():
                if indicator in normalized:
                    technique_id = mapping["technique_id"]

                    if technique_id not in techniques:
                        techniques[technique_id] = MitreTechnique(
                            technique_id=technique_id,
                            technique_name=mapping["technique_name"],
                            tactic=mapping["tactic"],
                        )

                    techniques[technique_id].add_evidence(command)

                    break

        return list(techniques.values())
