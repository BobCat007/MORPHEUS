# MORPHEUS

### Adaptive Adversary Deception & Intelligence

MORPHEUS is an adaptive cybersecurity deception platform designed to observe, understand, and respond to attacker behavior inside controlled honeypot environments.

Instead of operating as a static honeypot, MORPHEUS continuously builds intelligence from attacker sessions and uses that intelligence to adapt the deception environment.

> **Observe → Understand → Score → Adapt → Deceive → Learn**

---

## Overview

Traditional honeypots generally present a fixed environment to every attacker.

MORPHEUS takes a different approach.

It reconstructs attacker sessions, extracts behavioral intelligence, identifies attacker intent, maps activity to MITRE ATT&CK techniques, calculates risk, selects an appropriate honeypot personality, and can automatically activate that personality on the running deception service.

The current implementation uses **Cowrie** as the SSH deception layer and provides an extensible architecture for additional deception services and intelligence modules.

---

## Current Capabilities

### Deception

* Adaptive honeypot personalities
* Configurable deception levels
* Fake users
* Fake services
* Fake enterprise assets
* Human-like response delay profiles
* Automatic personality selection based on risk
* Runtime Cowrie adaptation

### Attacker Intelligence

* Cowrie telemetry ingestion
* Session reconstruction
* Attacker behavioral fingerprinting
* Command sequence analysis
* Command timing analysis
* Attacker intent classification
* Attack phase identification
* Attack campaign correlation
* Cross-session correlation

### Threat Intelligence

* IOC extraction from attacker commands
* IPv4, domain, URL, MD5 and SHA-256 IOC detection
* IP intelligence abstraction
* ASN/network intelligence
* DB-IP based network attribution
* MITRE ATT&CK technique mapping

### Risk & Response

* Explainable risk scoring
* Risk severity classification
* Adaptive defender response policies
* Deception personality selection
* Automatic deception planning
* Automatic Cowrie lifecycle activation

### Engineering

* Event-driven architecture
* Modular intelligence engines
* Pluggable intelligence providers
* Persistent JSONL event storage
* Automated test suite
* Docker-based deception deployment
* Python virtual environment support

---

## Adaptive Deception

The core MORPHEUS control loop currently works like this:

```text
                    Attacker
                       │
                       ▼
                ┌──────────────┐
                │    Cowrie    │
                │  Honeypot    │
                └──────┬───────┘
                       │
                       ▼
                ┌──────────────┐
                │  Telemetry   │
                │   Ingestion  │
                └──────┬───────┘
                       │
                       ▼
                ┌──────────────┐
                │    Session   │
                │ Reconstruction│
                └──────┬───────┘
                       │
             ┌─────────┴─────────┐
             ▼                   ▼
      Behavioral Intel      Intent Analysis
             │                   │
             └─────────┬─────────┘
                       ▼
                ┌──────────────┐
                │ Risk Scoring │
                └──────┬───────┘
                       │
                       ▼
              ┌─────────────────┐
              │   Personality   │
              │     Engine      │
              └───────┬─────────┘
                      │
                      ▼
              ┌─────────────────┐
              │    Deception    │
              │    Planner      │
              └───────┬─────────┘
                      │
                      ▼
              ┌─────────────────┐
              │    Cowrie       │
              │    Adapter      │
              └───────┬─────────┘
                      │
                      ▼
              ┌─────────────────┐
              │    Lifecycle    │
              │    Controller   │
              └───────┬─────────┘
                      │
                      ▼
                Live Honeypot
                Adaptation
```

---

## Live Adaptive Demonstration

MORPHEUS has been validated against a live Cowrie instance.

A high-risk assessment selected the:

```text
enterprise_database
```

personality.

The control plane then automatically applied:

```text
Hostname:       db-prod-01
Deception:      Level 3
Services:       SSH / MySQL / Redis
```

MORPHEUS restarted the Cowrie container automatically.

A new SSH session subsequently presented:

```text
test@db-prod-01:~$
```

This demonstrates that the adaptation pipeline is not merely generating a theoretical decision — the selected deception state is activated on the running honeypot.

---

## Risk Intelligence

MORPHEUS produces explainable risk assessments from multiple signals.

Example factors include:

```text
Successful authentication
        +
Attacker intent
        +
Behavioral fingerprint
        +
Campaign correlation
        +
Network attribution
        ↓
   Risk Score
        ↓
Severity Classification
        ↓
Adaptive Response
```

The system currently supports:

| Severity | Example adaptive behavior               |
| -------- | --------------------------------------- |
| Low      | Observe                                 |
| Medium   | Increase logging and deception          |
| High     | Expose fake assets and capture payloads |
| Critical | Trigger alerting and incident capture   |

These response policies are modular and can be extended as the platform grows.

---

## MITRE ATT&CK Integration

MORPHEUS maps observed attacker commands to MITRE ATT&CK techniques where supported.

Examples include:

```text
whoami / id
    → T1033 System Owner/User Discovery

uname
    → T1082 System Information Discovery

ls / pwd / find
    → T1083 File and Directory Discovery

wget / curl
    → T1105 Ingress Tool Transfer

chmod
    → T1222.001 File and Directory Permissions Modification

/etc/passwd
    → T1003.008 /etc/passwd
```

The mapping layer is designed to expand as additional behavioral rules and intelligence models are introduced.

---

## Architecture

```text
                    ┌───────────────────────┐
                    │       Attacker        │
                    └───────────┬───────────┘
                                │
                                ▼
                    ┌───────────────────────┐
                    │   Deception Gateway   │
                    └───────────┬───────────┘
                                │
                    ┌───────────▼───────────┐
                    │   Deception Services   │
                    │   Cowrie / SSH / etc.  │
                    └───────────┬───────────┘
                                │
                                ▼
                    ┌───────────────────────┐
                    │   Event / Telemetry    │
                    │        Pipeline        │
                    └───────────┬───────────┘
                                │
              ┌─────────────────┼─────────────────┐
              │                 │                 │
              ▼                 ▼                 ▼
        Session Intel     Behavioral Intel   Threat Intel
              │                 │                 │
              └─────────────────┼─────────────────┘
                                │
                                ▼
                    ┌───────────────────────┐
                    │     Risk Engine       │
                    └───────────┬───────────┘
                                │
                                ▼
                    ┌───────────────────────┐
                    │ Adaptive Control Plane│
                    ├───────────────────────┤
                    │ Personality Engine    │
                    │ Deception Planner      │
                    │ Service Adapter        │
                    │ Lifecycle Controller   │
                    └───────────┬───────────┘
                                │
                                ▼
                    ┌───────────────────────┐
                    │   Adaptive Honeypot    │
                    └───────────────────────┘
```

---

## Technology Stack

| Component           | Technology        |
| ------------------- | ----------------- |
| Language            | Python            |
| Honeypot            | Cowrie            |
| Containers          | Docker            |
| Testing             | pytest            |
| Threat Mapping      | MITRE ATT&CK      |
| IP/ASN Intelligence | DB-IP             |
| Storage             | JSONL event store |
| Environment         | Ubuntu / WSL2     |
| Version Control     | Git / GitHub      |

---

## Repository Structure

```text
MORPHEUS/
│
├── alerts/                 # Alerting integrations
├── api/                    # API layer
├── core/                   # Core platform infrastructure
│   ├── config/
│   ├── events/
│   ├── logging/
│   └── security/
│
├── deception/              # Adaptive deception system
│   ├── personality/
│   └── control/
│
├── deployment/             # Deployment configurations
│   └── cowrie/
│
├── intelligence/           # Attacker intelligence engines
│   ├── campaign/
│   ├── fingerprint/
│   ├── intent/
│   ├── mitre/
│   ├── response/
│   ├── risk/
│   ├── session/
│   └── timeline/
│
├── malware/                # Malware analysis components
├── purple_team/            # Purple-team functionality
├── reporting/              # Incident/reporting components
├── telemetry/              # Telemetry ingestion
├── threat_intel/           # Threat intelligence providers
│
├── tests/                  # Automated tests
├── docs/                   # Documentation
├── requirements.txt
└── pytest.ini
```

---

## Testing

MORPHEUS currently has:

```text
131 tests
131 passed
0 failed
```

The test suite covers core event processing, session reconstruction, fingerprinting, intent classification, MITRE mapping, IOC extraction, threat intelligence providers, risk scoring, adaptive response, honeypot personalities, and the deception control plane.

Run the test suite with:

```bash
pytest -q
```

---

## Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/BobCat007/MORPHEUS.git
cd MORPHEUS
```

### 2. Create a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Run tests

```bash
pytest -q
```

### 5. Deploy the Cowrie deception service

```bash
cd deployment/cowrie
docker compose up -d
```

The default SSH deception service is exposed on:

```text
localhost:2222
```

> MORPHEUS is intended for controlled, isolated security research environments. Do not expose an experimental honeypot directly to networks you do not control without appropriate containment and monitoring.

---

## Roadmap

MORPHEUS is being developed incrementally.

### Completed

* [x] Event-driven core
* [x] Cowrie telemetry ingestion
* [x] Session reconstruction
* [x] Behavioral fingerprinting
* [x] Intent classification
* [x] MITRE ATT&CK mapping
* [x] IOC extraction
* [x] IP intelligence abstraction
* [x] ASN/network intelligence
* [x] Explainable risk scoring
* [x] Adaptive defender response
* [x] Adaptive honeypot personalities
* [x] Deception planning
* [x] Automatic Cowrie lifecycle control
* [x] Live adaptive deception validation
* [x] Automated test coverage

### Planned

* [ ] Dynamic fake enterprise asset generation
* [ ] Cross-honeypot correlation
* [ ] Attack campaign detection improvements
* [ ] Attack timeline reconstruction enhancements
* [ ] Automatic incident report generation
* [ ] Expanded deception services
* [ ] Malware capture pipeline
* [ ] Safe static malware analysis
* [ ] Distributed honeynet support
* [ ] Threat knowledge base
* [ ] Purple-team mode
* [ ] SOC dashboard
* [ ] REST API
* [ ] Real-time WebSocket telemetry
* [ ] Advanced behavioral ML
* [ ] Advanced attacker intent prediction
* [ ] Adaptive zero-day/anomaly detection

---

## Security Philosophy

MORPHEUS is designed around controlled deception and observation.

The project prioritizes:

* Isolation of attacker-facing services
* Least-privilege execution
* Controlled network exposure
* Separation of management and deception infrastructure
* Persistent telemetry
* Explainable automated decisions
* Safe handling of collected artifacts
* Modular security boundaries

The platform should be deployed inside an appropriately isolated environment, particularly when exposed to untrusted traffic.

---

## Project Status

**Development status: Active**

MORPHEUS is currently in active development, with the adaptive deception control plane validated against a live Cowrie deployment.

The architecture is intentionally modular so additional deception services, intelligence providers, machine-learning models, storage backends, and response mechanisms can be introduced without rewriting the core platform.

---

## License

This project is currently maintained as an open-source cybersecurity research project.

See the repository license for the applicable terms.

---

## Author

**BobCat007**

MORPHEUS is built as a hands-on cybersecurity engineering project focused on adaptive deception, attacker intelligence, and automated defensive decision-making.
