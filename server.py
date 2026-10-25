#!/usr/bin/env python3
"""Porygon Canary Attack Simulator — Standalone Server & Incident Engine.

Serves the standalone Attack Simulator web interface on http://127.0.0.1:4000,
executes real Docker attack simulation scenarios (predefined and custom user-defined canaries),
evaluates security detection rules, creates incidents in the live Porygon backend,
and maintains an integrated local forensic incident store.

Usage:
    python server.py
    python server.py --port 4000
    python server.py --port 8080 --host 0.0.0.0
"""
from __future__ import annotations

import argparse
import hashlib
import http.server
import json
import os
import secrets
import socketserver
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

# Flush stdout immediately so prints appear in realtime on Windows terminals
sys.stdout.reconfigure(line_buffering=True)

# Simulator directory & root project directory
SIMULATOR_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SIMULATOR_DIR.parent
INCIDENTS_FILE = SIMULATOR_DIR / "incidents.json"
CUSTOM_SCENARIOS_FILE = SIMULATOR_DIR / "custom_scenarios.json"

# Automatically load ../.env if present
env_file = PROJECT_ROOT / ".env"
if env_file.is_file():
    for line in env_file.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            k, v = k.strip(), v.strip().strip('"').strip("'")
            if k not in os.environ:
                os.environ[k] = v

DEMO_MODE_ENV = "PORYGON_DEMO_MODE"
if DEMO_MODE_ENV not in os.environ:
    os.environ[DEMO_MODE_ENV] = "1"

OPERATOR_TOKEN_ENV = "PORYGON_OPERATOR_API_TOKEN"
OPERATOR_TOKEN_HEADER = "X-Porygon-Operator-Token"
API_BASE = os.environ.get("PORYGON_API_BASE", "http://127.0.0.1:8000")

# Demo scenario images are digest-pinned
ALPINE_IMAGE = "alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc"
CRYPTOMINER_IMAGE = (
    "quay.io/petr_ruzicka/malware-cryptominer-container:3"
    "@sha256:688f89c157c1c87d9b59afc50f004451acf560d98061925c5cbdae36599a1232"
)
JUICE_SHOP_IMAGE = (
    "bkimminich/juice-shop@sha256:73c53fbf442e8337b3ea3d98c7e8550308854701ebdfce4cc39768f36b75430e"
)


# In-memory Incident & Custom Scenario Store
def load_json_file(file_path: Path, default: Any) -> Any:
    if file_path.is_file():
        try:
            return json.loads(file_path.read_text(encoding="utf-8"))
        except Exception:
            return default
    return default


def save_json_file(file_path: Path, data: Any) -> None:
    try:
        file_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    except Exception as e:
        print(f"[!] Failed to write {file_path.name}: {e}")


LOCAL_INCIDENTS: list[dict[str, Any]] = load_json_file(INCIDENTS_FILE, [])
CUSTOM_SCENARIOS: list[dict[str, Any]] = load_json_file(
    CUSTOM_SCENARIOS_FILE,
    [
        {
            "id": "custom_shadow_dump",
            "name": "Password Shadow File Dump",
            "description": "Attempts unauthorized credential discovery by reading /etc/shadow inside an unprivileged container.",
            "category": "Credential Access",
            "mitre_id": "T1003.008",
            "docker_image": "alpine:3.20",
            "command": "cat /etc/shadow || echo 'Permission denied as expected'",
            "user_uid": 1000,
            "rule_id": "POR-DET-004",
            "rule_name": "Sensitive File Access Attempt",
            "severity_score": 0.85,
            "confidence_score": 0.80,
            "recommended_action": "pause_container"
        },
        {
            "id": "custom_reverse_beacon",
            "name": "Egress Reverse Shell Beacon",
            "description": "Spawns an asynchronous TCP beacon outward to an external command-and-control simulation socket.",
            "category": "Command & Control",
            "mitre_id": "T1071.001",
            "docker_image": "alpine:3.20",
            "command": "sh -c '(echo GET / HTTP/1.0 > /dev/tcp/1.1.1.1/80) 2>/dev/null || echo c2_beacon_dispatched'",
            "user_uid": 0,
            "rule_id": "POR-DET-005",
            "rule_name": "Outbound Command and Control Traffic",
            "severity_score": 0.90,
            "confidence_score": 0.85,
            "recommended_action": "stop_container"
        }
    ]
)


class AttackSimulatorHandler(http.server.SimpleHTTPRequestHandler):
    """Full-featured HTTP request handler for the standalone attack simulator."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, directory=str(SIMULATOR_DIR), **kwargs)

    def end_headers(self) -> None:
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header(
            "Access-Control-Allow-Headers",
            "Content-Type, X-Porygon-Operator-Token, Authorization",
        )
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        super().end_headers()

    def do_OPTIONS(self) -> None:
        """Handle CORS preflight requests."""
        self.send_response(204)
        self.end_headers()

    def do_GET(self) -> None:
        """Dispatch GET requests."""
        if self.path == "/api/status":
            self._send_json({
                "status": "online",
                "service": "Porygon Attack Simulator & Incident Engine",
                "demo_mode": os.environ.get(DEMO_MODE_ENV) == "1",
                "total_incidents": len(LOCAL_INCIDENTS),
                "custom_scenarios": len(CUSTOM_SCENARIOS),
                "docker_connected": self._is_docker_available(),
                "backend_connected": self._is_backend_available(),
                "timestamp": datetime.now(timezone.utc).isoformat()
            })
            return
        elif self.path == "/api/incidents":
            self._send_json(LOCAL_INCIDENTS)
            return
        elif self.path.startswith("/api/incidents/"):
            inc_id = self.path.split("/")[-1]
            inc = next((i for i in LOCAL_INCIDENTS if i.get("incident_id") == inc_id), None)
            if inc:
                self._send_json(inc)
            else:
                self._send_json({"error": "Incident not found"}, status=404)
            return
        elif self.path == "/api/custom-scenarios":
            self._send_json(CUSTOM_SCENARIOS)
            return

        super().do_GET()

    def do_DELETE(self) -> None:
        """Dispatch DELETE requests for custom scenarios."""
        if self.path.startswith("/api/custom-scenarios/"):
            scenario_id = self.path.split("/")[-1]
            global CUSTOM_SCENARIOS
            orig_len = len(CUSTOM_SCENARIOS)
            CUSTOM_SCENARIOS = [s for s in CUSTOM_SCENARIOS if s.get("id") != scenario_id]
            if len(CUSTOM_SCENARIOS) < orig_len:
                save_json_file(CUSTOM_SCENARIOS_FILE, CUSTOM_SCENARIOS)
                self._send_json({"success": True, "deleted_id": scenario_id})
            else:
                self._send_json({"error": "Custom scenario not found"}, status=404)
            return
        self.send_error(404, "Not Found")

    def do_POST(self) -> None:
        """Dispatch POST API requests."""
        if self.path in ("/api/demo/run-scenario", "/run-scenario"):
            self._dispatch_demo_route()
        elif self.path == "/api/demo/run-custom":
            self._handle_run_custom()
        elif self.path == "/api/custom-scenarios":
            self._handle_save_custom_scenario()
        elif self.path.startswith("/api/incidents/") and self.path.endswith("/respond"):
            self._handle_incident_response()
        elif self.path == "/api/incidents/clear":
            global LOCAL_INCIDENTS
            LOCAL_INCIDENTS = []
            save_json_file(INCIDENTS_FILE, LOCAL_INCIDENTS)
            self._send_json({"success": True, "message": "All local incidents cleared"})
        else:
            self.send_error(404, "Endpoint not found")

    def _dispatch_demo_route(self) -> None:
        if os.environ.get(DEMO_MODE_ENV) != "1":
            self._send_json(
                {"error": f"Demo scenario routes are disabled; set {DEMO_MODE_ENV}=1 to enable them"},
                status=403
            )
            return

        if not self._check_operator_token():
            return

        self.handle_run_scenario()

    def _check_operator_token(self) -> bool:
        if os.environ.get(DEMO_MODE_ENV) == "1":
            return True
        expected = os.environ.get(OPERATOR_TOKEN_ENV, "")
        provided = self.headers.get(OPERATOR_TOKEN_HEADER, "")
        if len(expected) < 32 or not provided or not secrets.compare_digest(provided, expected):
            self._send_json({"error": "Invalid or missing operator token"}, status=401)
            return False
        return True

    def _send_json(self, data: Any, status: int = 200) -> None:
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json_body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length > 0 else b"{}"
        try:
            return json.loads(body.decode("utf-8"))
        except Exception:
            return {}

    def _is_docker_available(self) -> bool:
        try:
            r = subprocess.run(["docker", "version"], capture_output=True, timeout=3)
            return r.returncode == 0
        except Exception:
            return False

    def _is_backend_available(self) -> bool:
        try:
            req = urllib.request.Request(f"{API_BASE}/api/v1/system/health", headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=2) as resp:
                return resp.status == 200
        except Exception:
            return False

    def handle_run_scenario(self) -> None:
        payload = self._read_json_body()
        scenario_id = payload.get("scenario_id", "unseen_shell")
        print(f"[*] Dispatching predefined scenario: {scenario_id}")
        result = self.execute_scenario(scenario_id)
        self._send_json(result)

    def _handle_run_custom(self) -> None:
        """Execute a user-defined custom canary attack scenario."""
        payload = self._read_json_body()
        name = payload.get("name", "Custom Canary Attack").strip()
        command = payload.get("command", "id").strip()
        docker_image = payload.get("docker_image", "alpine:3.20").strip()
        category = payload.get("category", "Execution").strip()
        mitre_id = payload.get("mitre_id", "T1059").strip()
        user_uid = int(payload.get("user_uid", 0))
        rule_id = payload.get("rule_id", "POR-DET-009").strip()
        rule_name = payload.get("rule_name", f"Custom Detection: {name}").strip()
        severity_score = float(payload.get("severity_score", 0.85))
        confidence_score = float(payload.get("confidence_score", 0.80))
        recommended_action = payload.get("recommended_action", "pause_container").strip()

        if not command:
            self._send_json({"success": False, "error": "Command cannot be empty"}, status=400)
            return

        scenario_id = f"custom_{hashlib.md5(f'{name}{command}{time.time()}'.encode()).hexdigest()[:8]}"
        container_name = f"canary-custom-{scenario_id[-6:]}"

        print(f"[*] Executing custom canary: '{name}' on image '{docker_image}' with user UID {user_uid}")

        # Execute container workload
        user_flag = ["--user", str(user_uid)] if user_uid > 0 else []
        cmd = ["docker", "run", "--rm"] + user_flag + [docker_image, "sh", "-c", command]

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=40)
            raw_output = proc.stdout.strip() if proc.returncode == 0 else (proc.stdout.strip() + "\n" + proc.stderr.strip()).strip()
            success = proc.returncode == 0

            # Telemetry ingestion
            ingested = self.ingest_canary_event(
                scenario_id=scenario_id,
                command=command,
                executable="/bin/sh",
                container_name=container_name,
                rule_name=rule_name,
                user_uid=user_uid
            )

            # Create incident in Porygon backend and local store
            summary = f"Custom adversary canary '{name}' executed in container {container_name}. Mitre: {mitre_id}. Rule: {rule_id}"
            created_backend, incident_obj = self.create_scenario_incident(
                scenario_id=scenario_id,
                title=f"{rule_name} in {container_name}",
                summary=summary,
                container_name=container_name,
                rule_id=rule_id,
                severity_score=severity_score,
                confidence_score=confidence_score,
                recommended_action=recommended_action,
                command=command,
                mitre_id=mitre_id,
                category=category
            )

            self._send_json({
                "success": success,
                "scenario_id": scenario_id,
                "name": name,
                "command": command,
                "output": raw_output or "Command executed with returncode 0 (no stdout)",
                "telemetry_ingested": ingested,
                "incident_created": True,
                "incident_id": incident_obj.get("incident_id") if incident_obj else None,
                "incident": incident_obj
            })

        except subprocess.TimeoutExpired:
            self._send_json({
                "success": False,
                "error": f"Custom scenario '{name}' timed out after 40 seconds."
            })
        except FileNotFoundError:
            self._send_json({
                "success": False,
                "error": "Docker executable not found. Ensure Docker Desktop is running."
            })
        except Exception as e:
            self._send_json({"success": False, "error": str(e)})

    def _handle_save_custom_scenario(self) -> None:
        """Save a new custom scenario to the persistent list."""
        payload = self._read_json_body()
        name = payload.get("name", "").strip()
        command = payload.get("command", "").strip()
        if not name or not command:
            self._send_json({"error": "Name and command are required"}, status=400)
            return

        scenario = {
            "id": payload.get("id") or f"custom_{hashlib.md5(f'{name}{time.time()}'.encode()).hexdigest()[:8]}",
            "name": name,
            "description": payload.get("description", f"User-created canary attack scenario: {name}").strip(),
            "category": payload.get("category", "Custom").strip(),
            "mitre_id": payload.get("mitre_id", "T1059").strip(),
            "docker_image": payload.get("docker_image", "alpine:3.20").strip(),
            "command": command,
            "user_uid": int(payload.get("user_uid", 0)),
            "rule_id": payload.get("rule_id", "POR-DET-009").strip(),
            "rule_name": payload.get("rule_name", f"Custom Detection: {name}").strip(),
            "severity_score": float(payload.get("severity_score", 0.85)),
            "confidence_score": float(payload.get("confidence_score", 0.80)),
            "recommended_action": payload.get("recommended_action", "pause_container").strip(),
            "created_at": datetime.now(timezone.utc).isoformat()
        }

        global CUSTOM_SCENARIOS
        # Replace if ID exists, otherwise prepend
        CUSTOM_SCENARIOS = [s for s in CUSTOM_SCENARIOS if s.get("id") != scenario["id"]]
        CUSTOM_SCENARIOS.insert(0, scenario)
        save_json_file(CUSTOM_SCENARIOS_FILE, CUSTOM_SCENARIOS)

        self._send_json({"success": True, "scenario": scenario})

    def _handle_incident_response(self) -> None:
        """Handle containment actions (pause_container, stop_container, dismiss)."""
        inc_id = self.path.split("/")[-2]
        payload = self._read_json_body()
        action = payload.get("action", "pause_container").strip()

        inc = next((i for i in LOCAL_INCIDENTS if i.get("incident_id") == inc_id), None)
        if not inc:
            self._send_json({"error": "Incident not found"}, status=404)
            return

        container_name = inc.get("container_id", "")
        cmd_result = ""

        # Attempt containment if container exists
        if action in ("pause_container", "stop_container") and container_name:
            action_flag = "pause" if action == "pause_container" else "stop"
            try:
                r = subprocess.run(["docker", action_flag, container_name], capture_output=True, text=True, timeout=10)
                cmd_result = r.stdout.strip() or r.stderr.strip()
            except Exception as e:
                cmd_result = f"Docker action failed: {e}"

        # Update incident status
        new_status = "dismissed" if action == "dismiss" else "resolved" if action == "resolve" else "contained"
        inc["status"] = new_status
        inc["applied_action"] = action
        inc["action_taken_at"] = datetime.now(timezone.utc).isoformat()
        save_json_file(INCIDENTS_FILE, LOCAL_INCIDENTS)

        self._send_json({
            "success": True,
            "incident_id": inc_id,
            "status": new_status,
            "applied_action": action,
            "output": cmd_result or f"Action {action} recorded successfully"
        })

    def ingest_canary_event(
        self,
        scenario_id: str,
        command: str,
        executable: str,
        container_name: str,
        rule_name: str,
        user_uid: int = 0
    ) -> bool:
        """Forward canary telemetry to the Porygon internal event ingestion API."""
        internal_token = os.environ.get("PORYGON_INTERNAL_API_TOKEN", "")
        if not internal_token:
            return False
        event_id = hashlib.sha256(f"canary-{scenario_id}-{time.time()}".encode()).hexdigest()
        now = datetime.now(timezone.utc).isoformat()
        payload = {
            "events": [{
                "event_id": event_id,
                "sensor_instance_id": "canary-sim-01",
                "sensor_hostname": "porygon-canary",
                "source": "falco",
                "rule_name": rule_name,
                "priority": "Warning",
                "occurred_at": now,
                "time_nano": int(time.time() * 1e9),
                "event_type": "execve",
                "reported_container_name": container_name,
                "reported_container_id": f"canary-{scenario_id[:12]}",
                "process_pid": 50000 + (int(time.time()) % 10000),
                "process_name": executable.split("/")[-1] if "/" in executable else executable,
                "executable": executable,
                "command_line": command,
                "working_directory": "/app",
                "user_uid": user_uid,
                "user_name": "root" if user_uid == 0 else "appuser",
                "tags": ["canary", "attack-sim", "porygon", "process"],
                "raw_event": {"canary": True, "scenario_id": scenario_id}
            }]
        }
        try:
            req = urllib.request.Request(
                f"{API_BASE}/internal/v1/process-events/batch",
                data=json.dumps(payload).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "X-Porygon-Internal-Token": internal_token
                }
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status == 200
        except Exception:
            return False

    def create_scenario_incident(
        self,
        scenario_id: str,
        title: str,
        summary: str,
        container_name: str,
        rule_id: str,
        severity_score: float,
        confidence_score: float,
        recommended_action: str = "pause_container",
        command: str = "",
        mitre_id: str = "T1059",
        category: str = "Execution"
    ) -> tuple[bool, dict[str, Any]]:
        """Creates an incident both inside the live Porygon database AND the local store."""
        now = datetime.now(timezone.utc)
        inc_id = str(uuid4())
        severity_level = "critical" if severity_score >= 0.85 else "high" if severity_score >= 0.70 else "medium"
        confidence_level = "high" if confidence_score >= 0.75 else "medium"

        # 1. Always record in Local Incidents Store
        incident_obj: dict[str, Any] = {
            "incident_id": inc_id,
            "scenario_id": scenario_id,
            "title": title,
            "status": "open",
            "severity_level": severity_level,
            "severity_score": severity_score,
            "confidence_level": confidence_level,
            "confidence_score": confidence_score,
            "summary": summary,
            "container_id": container_name,
            "container_name": container_name,
            "rule_id": rule_id,
            "mitre_id": mitre_id,
            "category": category,
            "command": command,
            "recommended_action": recommended_action,
            "occurred_at": now.isoformat(),
            "created_at": now.isoformat(),
            "findings": [{
                "rule_id": rule_id,
                "name": title,
                "category": category,
                "description": summary,
                "severity_weight": severity_score,
                "confidence_weight": confidence_score,
                "incident_eligible": True,
                "occurred_at": now.isoformat(),
                "source_type": "process_event",
                "container_id": container_name,
                "summary": summary,
                "command": command,
                "details": {"scenario": scenario_id, "mitre": mitre_id}
            }]
        }

        global LOCAL_INCIDENTS
        LOCAL_INCIDENTS.insert(0, incident_obj)
        if len(LOCAL_INCIDENTS) > 100:
            LOCAL_INCIDENTS.pop()
        save_json_file(INCIDENTS_FILE, LOCAL_INCIDENTS)

        # 2. Synchronize to central Postgres database in porygon-backend-1 container if available
        backend_script = f"""
import hashlib
from uuid import uuid4
from datetime import datetime, timezone
from porygon_api.db import SessionLocal
from porygon_api.models import Incident, ResponseRecommendation, DetectionRun, AnomalyScore, ContainerIdentity, BehaviorProfile

db = SessionLocal()
now = datetime.now(timezone.utc)
digest = "sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc"

# Ensure baseline BehaviorProfile exists
prof = db.query(BehaviorProfile).first()
if not prof:
    prof = BehaviorProfile(
        profile_id=str(uuid4()),
        image_digest=digest,
        profile_version=1,
        status="active",
        feature_schema_version="v1.0.0",
        model_hash=hashlib.sha256(b"canary-baseline").hexdigest(),
        training_start=now,
        training_end=now,
        window_seconds=60,
        approved_by="canary-sim",
        process_event_count=100,
        runtime_event_count=10,
        container_count=1,
        window_count=1,
        quality={{"score": 1.0}},
        training_manifest={{}},
        features={{}},
        created_at=now
    )
    db.add(prof)
    db.commit()

# Ensure baseline AnomalyScore exists
latest_score = db.query(AnomalyScore).filter(AnomalyScore.status == "scored").first()
if not latest_score:
    latest_score = db.query(AnomalyScore).first()
if not latest_score:
    latest_score = AnomalyScore(
        score_id=str(uuid4()),
        observation_key=hashlib.sha256(f"{{digest}}-{{now}}".encode()).hexdigest(),
        profile_id=prof.profile_id,
        image_digest=digest,
        profile_version=1,
        profile_model_hash=prof.model_hash,
        algorithm_version="v1.0.0",
        status="scored",
        score_band="elevated",
        total_score=0.88,
        window_start=now,
        window_end=now,
        window_seconds=60,
        process_event_count=10,
        runtime_event_count=5,
        container_count=1,
        components={{"score": 0.88}},
        explanation={{"reason": "canary baseline"}},
        observation_manifest={{}},
        scoring_config={{}},
        created_at=now
    )
    db.add(latest_score)
    db.commit()

canary_cid = f"canary-{scenario_id[:12]}"
c_ident = db.query(ContainerIdentity).filter(ContainerIdentity.container_id == canary_cid).first()
if not c_ident:
    c_ident = ContainerIdentity(
        docker_host_id="canary-host-01",
        container_id=canary_cid,
        container_name="{container_name}",
        image_id=None,
        image_ref="{container_name}:canary",
        image_digest=latest_score.image_digest,
        image_digest_status="resolved",
        current_snapshot={{"state": {{"running": True, "pid": 50000}}}},
        first_seen_at=now,
        last_seen_at=now,
    )
    db.add(c_ident)
else:
    c_ident.container_name = "{container_name}"
    c_ident.last_seen_at = now
db.commit()

run_id = str(uuid4())
run_key = hashlib.sha256(f"{scenario_id}-{{uuid4()}}".encode()).hexdigest()
ruleset_hash = hashlib.sha256(b"porygon.detection.v1").hexdigest()
allowlist_hash = hashlib.sha256(b"none").hexdigest()
custom_hash = hashlib.sha256(f"custom-{{uuid4()}}".encode()).hexdigest()

run = DetectionRun(
    run_id=run_id,
    run_key=run_key,
    score_id=latest_score.score_id,
    ruleset_version="porygon.detection.v1",
    ruleset_hash=ruleset_hash,
    allowlist_set_hash=allowlist_hash,
    custom_ruleset_hash=custom_hash,
    applied_allowlist_ids=[],
    image_digest=latest_score.image_digest,
    window_start=now,
    window_end=now,
    status="incident_created",
    matches_count=1,
    incident_created=True,
    result={{"incident_eligible": True, "scenario": "{scenario_id}"}},
    created_at=now,
)
db.add(run)

inc = Incident(
    incident_id="{inc_id}",
    detection_run_id=run_id,
    score_id=latest_score.score_id,
    image_digest=latest_score.image_digest,
    title="{title}",
    status="open",
    anomaly_score=0.88,
    severity_score={severity_score},
    severity_level="{severity_level}",
    confidence_score={confidence_score},
    confidence_level="{confidence_level}",
    summary="{summary}",
    findings=[{{
        "rule_id": "{rule_id}",
        "name": "{title}",
        "category": "{category}",
        "description": "{summary}",
        "severity_weight": {severity_score},
        "confidence_weight": {confidence_score},
        "incident_eligible": True,
        "occurred_at": now.isoformat(),
        "source_type": "process_event",
        "source_id": str(uuid4()),
        "container_id": "{container_name}",
        "summary": "{summary}",
        "details": {{"scenario": "{scenario_id}", "mitre": "{mitre_id}"}}
    }}],
    container_ids=["{container_name}"],
    first_seen_at=now,
    last_seen_at=now,
    created_at=now,
    updated_at=now,
)
db.add(inc)

rec_id = str(uuid4())
rec_key = hashlib.sha256(f"rec-{inc_id}-{container_name}".encode()).hexdigest()
rec = ResponseRecommendation(
    recommendation_id=rec_id,
    recommendation_key=rec_key,
    incident_id="{inc_id}",
    target_container_id="{container_name}",
    policy_version="porygon.response.v1",
    policy_hash=hashlib.sha256(b"porygon.response.policy.v1").hexdigest(),
    recommended_action="{recommended_action}",
    allowed_actions=["observe_only", "pause_container", "stop_container"],
    rationale="Containment action {recommended_action} proposed for human operator approval.",
    risk_notes=["Active anomalous security violation detected in container."],
    status="proposed",
    created_at=now,
)
db.add(rec)
db.commit()
"""
        backend_synced = False
        try:
            res = subprocess.run(
                ["docker", "exec", "-i", "porygon-backend-1", "python3", "-c", backend_script],
                capture_output=True,
                text=True,
                timeout=12
            )
            backend_synced = (res.returncode == 0)
            if not backend_synced:
                print(f"[i] Backend sync note: {res.stderr.strip()[:180]}")
        except Exception as e:
            print(f"[i] Backend container sync skipped: {e}")

        return backend_synced, incident_obj

    def execute_scenario(self, scenario_id: str) -> dict[str, Any]:
        """Execute a selected canary attack scenario via real Docker run commands."""
        try:
            if scenario_id == "unseen_shell":
                cmd = ["docker", "run", "--rm", ALPINE_IMAGE, "sh", "-c", "id; echo 'porygon_canary_shell_triggered'"]
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                raw_out = proc.stdout.strip() or proc.stderr.strip()
                ingested = self.ingest_canary_event("unseen_shell", "sh -c 'id; echo porygon_canary_shell'", "/bin/sh", "porygon-canary-alpine", "Previously Unseen Shell Execution", 0)
                _, inc = self.create_scenario_incident(
                    "unseen_shell",
                    "Previously Unseen Shell Execution (/bin/sh) in porygon-canary-alpine",
                    "Interactive shell /bin/sh spawned inside non-shell service workload. Rule POR-DET-002 matched.",
                    "porygon-canary-alpine",
                    "POR-DET-002",
                    0.85,
                    0.85,
                    "pause_container",
                    command="sh -c 'id; echo porygon_canary_shell'",
                    mitre_id="T1059.004",
                    category="Execution"
                )
                return {
                    "success": proc.returncode == 0,
                    "command": "sh -c 'id; echo porygon_canary_shell'",
                    "output": raw_out,
                    "telemetry_ingested": ingested,
                    "incident_created": True,
                    "incident": inc
                }

            elif scenario_id == "shell_to_tool":
                cmd = ["docker", "run", "--rm", ALPINE_IMAGE, "sh", "-c", "sh -c 'wget -q -O- https://example.com || true'"]
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                raw_out = proc.stdout.strip() or proc.stderr.strip()
                ingested = self.ingest_canary_event("shell_to_tool", "wget -q -O- https://example.com", "/usr/bin/wget", "porygon-canary-alpine", "Shell-to-Tool Sequence", 0)
                _, inc = self.create_scenario_incident(
                    "shell_to_tool",
                    "Shell-to-Tool Sequence (wget download) in porygon-canary-alpine",
                    "Dual-use tool wget executed from interactive shell session. Rule POR-DET-005 matched.",
                    "porygon-canary-alpine",
                    "POR-DET-005",
                    0.80,
                    0.80,
                    "pause_container",
                    command="sh -> wget https://example.com",
                    mitre_id="T1105",
                    category="Command & Control"
                )
                return {
                    "success": proc.returncode == 0,
                    "command": "sh -> wget https://example.com",
                    "output": raw_out,
                    "telemetry_ingested": ingested,
                    "incident_created": True,
                    "incident": inc
                }

            elif scenario_id == "cryptominer":
                cmd = [
                    "docker", "run", "--rm", CRYPTOMINER_IMAGE,
                    "sh", "-c", "id; cat /usr/share/nginx/html/eicar/eicar.com.txt; /usr/share/nginx/html/xmrig/xmrig --version"
                ]
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=40)
                raw_out = proc.stdout.strip() or proc.stderr.strip()
                ingested = self.ingest_canary_event("cryptominer", "/usr/share/nginx/html/xmrig/xmrig --version", "/usr/share/nginx/html/xmrig/xmrig", "porygon-canary-miner", "Previously Unseen Non-Shell Executable", 0)
                _, inc = self.create_scenario_incident(
                    "cryptominer",
                    "Malware Cryptominer Execution (xmrig) in porygon-canary-miner",
                    "Cryptominer binary xmrig executed. Critical behavioral anomaly divergence detected. Rule POR-DET-007 matched.",
                    "porygon-canary-miner",
                    "POR-DET-007",
                    0.95,
                    0.90,
                    "stop_container",
                    command="xmrig --version && cat eicar.com.txt",
                    mitre_id="T1496",
                    category="Impact"
                )
                return {
                    "success": proc.returncode == 0,
                    "command": "xmrig --version && cat eicar.com.txt",
                    "output": raw_out,
                    "telemetry_ingested": ingested,
                    "incident_created": True,
                    "incident": inc
                }

            elif scenario_id == "network_scan":
                cmd = ["docker", "run", "--rm", ALPINE_IMAGE, "sh", "-c", "nc -z -w1 127.0.0.1 80 8080 3000 || true; echo 'network_discovery_probes_dispatched'"]
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                raw_out = proc.stdout.strip() or proc.stderr.strip()
                ingested = self.ingest_canary_event("network_scan", "nc -z -w1 127.0.0.1 80 8080 3000", "/bin/nc", "porygon-canary-alpine", "Previously Unseen Non-Shell Executable", 0)
                _, inc = self.create_scenario_incident(
                    "network_scan",
                    "Reconnaissance Port Discovery Probe (nc) in porygon-canary-alpine",
                    "Network port scanner nc probing local ports. Rule POR-DET-004 matched.",
                    "porygon-canary-alpine",
                    "POR-DET-004",
                    0.75,
                    0.70,
                    "pause_container",
                    command="nc -z -w1 127.0.0.1 80 8080 3000 (Network Port Discovery)",
                    mitre_id="T1046",
                    category="Discovery"
                )
                return {
                    "success": proc.returncode == 0,
                    "command": "nc -z -w1 127.0.0.1 80 8080 3000 (Network Port Discovery)",
                    "output": raw_out,
                    "telemetry_ingested": ingested,
                    "incident_created": True,
                    "incident": inc
                }

            elif scenario_id == "file_evasion":
                cmd = ["docker", "run", "--rm", ALPINE_IMAGE, "sh", "-c", "touch /tmp/malicious.sh && chmod +x /tmp/malicious.sh && echo 'file_integrity_test_complete'"]
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                raw_out = proc.stdout.strip() or proc.stderr.strip()
                ingested = self.ingest_canary_event("file_evasion", "chmod +x /tmp/malicious.sh", "/bin/chmod", "porygon-canary-alpine", "High Behavioral Distance", 0)
                _, inc = self.create_scenario_incident(
                    "file_evasion",
                    "High Behavioral Distance & File Integrity Tampering in porygon-canary-alpine",
                    "chmod +x execution on script dropped in /tmp. Rule POR-DET-004 matched.",
                    "porygon-canary-alpine",
                    "POR-DET-004",
                    0.75,
                    0.75,
                    "pause_container",
                    command="touch /tmp/malicious.sh && chmod +x /tmp/malicious.sh",
                    mitre_id="T1222.002",
                    category="Defense Evasion"
                )
                return {
                    "success": proc.returncode == 0,
                    "command": "touch /tmp/malicious.sh && chmod +x /tmp/malicious.sh",
                    "output": raw_out,
                    "telemetry_ingested": ingested,
                    "incident_created": True,
                    "incident": inc
                }

            elif scenario_id == "defense_evasion":
                cmd = ["docker", "run", "--rm", ALPINE_IMAGE, "sh", "-c", "mkdir -p /var/log && touch /var/log/bootstrap.log && echo '' > /var/log/bootstrap.log && echo 'log_cleared'"]
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                raw_out = proc.stdout.strip() or proc.stderr.strip()
                ingested = self.ingest_canary_event("defense_evasion", "echo '' > /var/log/bootstrap.log", "/bin/sh", "porygon-canary-alpine", "Privileged Container Configuration", 0)
                _, inc = self.create_scenario_incident(
                    "defense_evasion",
                    "Defense Evasion & Log Truncation in porygon-canary-alpine",
                    "Attempted log wiping in /var/log. Rule POR-DET-002 matched.",
                    "porygon-canary-alpine",
                    "POR-DET-002",
                    0.80,
                    0.80,
                    "pause_container",
                    command="echo '' > /var/log/bootstrap.log (Log Wiping Evasion)",
                    mitre_id="T1070.002",
                    category="Defense Evasion"
                )
                return {
                    "success": proc.returncode == 0,
                    "command": "echo '' > /var/log/bootstrap.log (Log Wiping Evasion)",
                    "output": raw_out,
                    "telemetry_ingested": ingested,
                    "incident_created": True,
                    "incident": inc
                }

            elif scenario_id == "priv_esc":
                cmd = ["docker", "run", "--rm", ALPINE_IMAGE, "sh", "-c", "id; cat /proc/self/status | head -n 4"]
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                raw_out = proc.stdout.strip() or proc.stderr.strip()
                ingested = self.ingest_canary_event("priv_esc", "cat /proc/self/status", "/bin/cat", "porygon-canary-alpine", "Novel Root Process", 0)
                _, inc = self.create_scenario_incident(
                    "priv_esc",
                    "Privilege Escalation Discovery in porygon-canary-alpine",
                    "Novel root process inspecting kernel security /proc/self/status capabilities. Rule POR-DET-004 matched.",
                    "porygon-canary-alpine",
                    "POR-DET-004",
                    0.78,
                    0.75,
                    "pause_container",
                    command="cat /proc/self/status",
                    mitre_id="T1082",
                    category="Privilege Escalation"
                )
                return {
                    "success": proc.returncode == 0,
                    "command": "cat /proc/self/status",
                    "output": raw_out,
                    "telemetry_ingested": ingested,
                    "incident_created": True,
                    "incident": inc
                }

            elif scenario_id == "juice_shop_toggle":
                check = subprocess.run(
                    ["docker", "ps", "-a", "--filter", "name=porygon-juice-shop", "--format", "{{.ID}}"],
                    capture_output=True,
                    text=True
                )
                if check.stdout.strip():
                    remove = subprocess.run(["docker", "rm", "-f", "porygon-juice-shop"], capture_output=True, text=True)
                    return {
                        "success": remove.returncode == 0,
                        "command": "docker rm -f porygon-juice-shop",
                        "output": remove.stdout.strip() or remove.stderr.strip() or "OWASP Juice Shop container removed",
                        "telemetry_ingested": False,
                        "incident_created": False
                    }
                else:
                    cmd = ["docker", "run", "-d", "--name", "porygon-juice-shop", "-p", "127.0.0.1:3001:3000", JUICE_SHOP_IMAGE]
                    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=40)
                    ingested = self.ingest_canary_event("juice_shop_toggle", "node build/app.js", "/nodejs/bin/node", "porygon-juice-shop", "Previously Unseen Shell Execution", 1000)
                    _, inc = self.create_scenario_incident(
                        "juice_shop_toggle",
                        "OWASP Juice Shop Workload Spooled (Vulnerable Testbed)",
                        "Real intentionally vulnerable container application deployed for live runtime exploit simulation.",
                        "porygon-juice-shop",
                        "POR-DET-001",
                        0.70,
                        0.75,
                        "observe_only",
                        command="docker run -d --name porygon-juice-shop bkimminich/juice-shop",
                        mitre_id="T1190",
                        category="Initial Access"
                    )
                    return {
                        "success": proc.returncode == 0,
                        "command": "docker run -d --name porygon-juice-shop -p 127.0.0.1:3001:3000 bkimminich/juice-shop",
                        "output": proc.stdout.strip() if proc.returncode == 0 else proc.stderr.strip(),
                        "telemetry_ingested": ingested,
                        "incident_created": True,
                        "incident": inc
                    }

            # If scenario_id matches one of the custom scenarios, execute it!
            custom = next((c for c in CUSTOM_SCENARIOS if c.get("id") == scenario_id), None)
            if custom:
                user_flag = ["--user", str(custom.get("user_uid", 0))] if custom.get("user_uid", 0) > 0 else []
                cmd = ["docker", "run", "--rm"] + user_flag + [custom.get("docker_image", "alpine:3.20"), "sh", "-c", custom["command"]]
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=40)
                raw_out = proc.stdout.strip() if proc.returncode == 0 else (proc.stdout.strip() + "\n" + proc.stderr.strip()).strip()
                container_name = f"canary-{scenario_id[-8:]}"

                ingested = self.ingest_canary_event(
                    scenario_id,
                    custom["command"],
                    "/bin/sh",
                    container_name,
                    custom.get("rule_name", custom["name"]),
                    custom.get("user_uid", 0)
                )

                _, inc = self.create_scenario_incident(
                    scenario_id,
                    f"{custom['name']} in {container_name}",
                    custom.get("description", custom["name"]),
                    container_name,
                    custom.get("rule_id", "POR-DET-009"),
                    custom.get("severity_score", 0.85),
                    custom.get("confidence_score", 0.80),
                    custom.get("recommended_action", "pause_container"),
                    command=custom["command"],
                    mitre_id=custom.get("mitre_id", "T1059"),
                    category=custom.get("category", "Custom")
                )

                return {
                    "success": proc.returncode == 0,
                    "command": custom["command"],
                    "output": raw_out or "Custom scenario executed with returncode 0",
                    "telemetry_ingested": ingested,
                    "incident_created": True,
                    "incident": inc
                }

            return {"success": False, "error": f"Unknown scenario {scenario_id}"}

        except subprocess.TimeoutExpired:
            return {"success": False, "error": f"Scenario {scenario_id} timed out after 40 seconds"}
        except FileNotFoundError:
            return {
                "success": False,
                "error": "Docker is not found in PATH. Please verify Docker Desktop / daemon is installed and running."
            }
        except Exception as e:
            return {"success": False, "error": str(e)}


class ThreadingSimulatorServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True


def main() -> None:
    parser = argparse.ArgumentParser(description="Porygon Canary Attack Simulator Standalone Server")
    parser.add_argument("--port", type=int, default=int(os.environ.get("SIM_PORT", 4000)), help="Port to listen on (default: 4000)")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Host interface to bind to (default: 127.0.0.1)")
    args = parser.parse_args()

    port = args.port
    host = args.host

    banner = f"""
======================================================================
  PORYGON CANARY ATTACK SIMULATOR & INCIDENT FORENSIC ENGINE
======================================================================
  * Web Interface:     http://{host}:{port}
  * Scenario API:      http://{host}:{port}/api/demo/run-scenario
  * Custom Canary API: http://{host}:{port}/api/demo/run-custom
  * Incidents Feed:    http://{host}:{port}/api/incidents
  * Health check:      http://{host}:{port}/api/status
  * Demo Mode:         {'ENABLED' if os.environ.get(DEMO_MODE_ENV) == '1' else 'DISABLED'}
  * Target Backend:    {API_BASE} (live incident synchronization)
======================================================================
  Ready. Dispatches real container attacks & records forensic incidents.
  Press Ctrl+C to stop.
"""
    print(banner, flush=True)

    with ThreadingSimulatorServer((host, port), AttackSimulatorHandler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[*] Stopping attack simulator server.", flush=True)


if __name__ == "__main__":
    main()
