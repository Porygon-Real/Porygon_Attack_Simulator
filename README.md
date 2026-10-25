# Porygon Canary Attack Simulator & Forensics Lab (Standalone)

A self-contained web application, adversary emulation harness, and forensic incident engine extracted from Porygon. It dispatches real containerized attacks (both 8 built-in verified canaries and arbitrary custom user-defined canaries) to audit runtime container security sensors (Falco, eBPF, behavioral anomaly scoring).

---

## Architecture

```
attack-simulator/
├── index.html              # Modern reactive frontend with 4 tabs: Canaries, Custom Builder, Incidents, Terminal
├── style.css               # Editorial newsprint design system (tokens, buttons, badges, modals, cards)
├── server.py               # Standalone Python backend (static server + Docker runner + Incidents Engine + CORS)
├── incidents.json          # Persistent local forensic incident store
├── custom_scenarios.json   # Persistent saved custom canary attack scenarios
└── README.md               # Complete documentation and usage guide
```

---

## Prerequisites

- **Python 3.8+** (uses only standard library — zero external pip packages needed)
- **Docker Desktop / Docker Engine** (running on your host or WSL2)

---

## Quick Start

### 1. Launch the Server

Run the Python server from inside the `attack-simulator` directory:

```bash
cd attack-simulator
python server.py
```

The server binds to `http://127.0.0.1:4000` by default.

To run on a custom port or external interface:
```bash
python server.py --port 8080 --host 0.0.0.0
```

### 2. Open the Web Application

Navigate to:
```
http://127.0.0.1:4000
```
*(Or double-click `index.html` to open directly in any modern browser — full CORS support is enabled).*

---

## Key Capabilities & Features

### 1. Built-in Predefined Verification Canaries (Tab 01)
Dispatches 8 classic, digest-pinned container attacks:
- **CANARY 01**: Interactive Shell Spawn (`/bin/sh`, MITRE T1059.004)
- **CANARY 02**: Shell-to-Tool Dropper (`wget`, MITRE T1105)
- **CANARY 03**: XMRig Cryptominer Execution (`xmrig + EICAR`, MITRE T1496)
- **CANARY 04**: Reconnaissance Port Discovery Probe (`nc`, MITRE T1046)
- **CANARY 05**: File Dropper Tampering (`/tmp/malicious.sh + chmod +x`, MITRE T1222.002)
- **CANARY 06**: Log Wiping Evasion (`/var/log/bootstrap.log truncate`, MITRE T1070.002)
- **CANARY 07**: Privilege Escalation Probe (`/proc/self/status`, MITRE T1082)
- **CANARY 08**: OWASP Juice Shop Live Application Spooler / Remover (MITRE T1190)

### 2. Custom Canary Attack Builder (Tab 02)
Allows creating and firing **arbitrary new container attack scenarios** that are not predefined:
- **Custom Docker Image**: Use `alpine:3.20`, `ubuntu:latest`, `busybox`, `python:3.11-alpine`, or any custom image.
- **Custom Shell Command**: Run any shell script, payload, or binary.
- **User Execution Context**: Choose `root (UID 0)`, `appuser (UID 1000)`, or sandboxed context.
- **MITRE ATT&CK Mapping**: Map to Execution, Discovery, Privilege Escalation, Defense Evasion, Command & Control, Credential Access, or Impact.
- **Quick Presets**: Instant 1-click presets for *Shadow File Dump*, *C2 Reverse Beacon*, *Sudoers Tampering*, *Kernel Exploit Probe*, and *Memory Exhaustion*.
- **Save as Reusable Card**: Save custom canaries to the persistent scenario deck with 1-click re-execution.

### 3. Incident Forensics & Containment Actions (Tab 03)
- Automatically evaluates detection rules for every canary attack.
- Generates formal **Incidents** with unique UUIDs, anomaly scores, confidence ratings, and MITRE categorization.
- Real-time containment controls:
  - **Pause Container**: Issues `docker pause` to immediately freeze anomalous execution.
  - **Stop Container**: Issues `docker stop` to terminate compromised workloads.
  - **Dismiss Incident**: Operator review clearance.
- **Forensics JSON Inspector**: Drill down into raw findings, container snapshots, and telemetry envelopes.

### 4. Teletype Adversary Terminal (Tab 04)
Live console streaming:
- Raw stdout and stderr from inside the Docker containers
- Process return codes and command lines
- Security telemetry ingest confirmations
- Automated containment action audit logs
