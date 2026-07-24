#!/usr/bin/env python3
"""Always-on localhost supervisor for Nutanix STIG Control Center."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import secrets
import signal
import threading
import time
import uuid
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

import control_center
import supervisor_setup


ROOT = Path(__file__).resolve().parent
ASSET_DIR = ROOT / "supervisor_static"
CSRF_TOKEN = secrets.token_urlsafe(32)
INSTANCE_ID = uuid.uuid4().hex
JOBS: dict[str, dict] = {}
JOBS_LOCK = threading.Lock()
ACTION_LOCK = threading.Lock()
LOG_LOCK = threading.Lock()
CURRENT_JOB_ID: str | None = None
LAST_ERROR = ""
DEPENDENCY_CACHE = {"checked_at": 0.0, "ready": False}
MAX_PROGRESS_LINES = 250
MAX_JOBS = 50
MAX_REQUEST_BYTES = 64 * 1024

ASSETS = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/app.css": ("app.css", "text/css; charset=utf-8"),
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def append_log(message: str) -> None:
    safe = redact(message)
    supervisor_setup.runtime_dir(ROOT).mkdir(parents=True, exist_ok=True)
    with LOG_LOCK:
        try:
            with supervisor_setup.log_file(ROOT).open("a", encoding="utf-8") as handle:
                handle.write(f"[{utc_now()}] {safe}\n")
        except OSError:
            pass


def redact(message: str) -> str:
    text = str(message).replace("\r", " ").replace("\x00", "")
    text = re.sub(
        r"(?i)(https?://)([^/\s:@]+):([^@\s/]+)@",
        r"\1[redacted]:[redacted]@",
        text,
    )
    return text[:1000]


def add_progress(job_id: str, message: str) -> None:
    safe = redact(message)
    append_log(f"job {job_id}: {safe}")
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            return
        job["progress"].append(
            {
                "at": utc_now(),
                "message": safe,
            }
        )
        del job["progress"][:-MAX_PROGRESS_LINES]
        job["updated_at"] = utc_now()


def dependency_ready(force: bool = False) -> bool:
    now = time.monotonic()
    if force or now - DEPENDENCY_CACHE["checked_at"] > 30:
        DEPENDENCY_CACHE["ready"] = control_center.dependencies_work()
        DEPENDENCY_CACHE["checked_at"] = now
    return bool(DEPENDENCY_CACHE["ready"])


def public_job(job: dict | None) -> dict | None:
    if not job:
        return None
    return {
        key: job.get(key)
        for key in (
            "id",
            "action",
            "status",
            "created_at",
            "started_at",
            "updated_at",
            "completed_at",
            "progress",
            "result",
            "error",
        )
    }


def status_snapshot() -> dict:
    global CURRENT_JOB_ID
    app_state, app_health = control_center.running_state()
    with JOBS_LOCK:
        current = public_job(JOBS.get(CURRENT_JOB_ID)) if CURRENT_JOB_ID else None
        last_error = LAST_ERROR
    if current and current["status"] in {"queued", "running"} and current["action"] in {
        "start",
        "restart",
    }:
        state = "Starting"
    elif app_state:
        state = "Running"
    elif last_error:
        state = "Error"
    else:
        state = "Stopped"
    registration = supervisor_setup.registration_status(ROOT)
    return {
        "version": control_center.VERSION,
        "state": state,
        "dependencies_ready": dependency_ready(),
        "registration": {
            "registered": bool(registration),
            "kind": registration.get("kind"),
        },
        "app": {
            "running": bool(app_state),
            "url": app_state.get("url") if app_state else None,
            "pid": app_state.get("pid") if app_state else None,
            "active_cluster": app_health.get("active_cluster") if app_health else None,
            "operation_running": bool(
                app_health and app_health.get("operation_running")
            ),
        },
        "current_job": current,
        "last_error": last_error or None,
        "polled_at": utc_now(),
    }


def execute_action(action: str, job_id: str) -> dict:
    progress = lambda message: add_progress(job_id, message)
    with control_center.controller_lock():
        if action == "install":
            control_center.install_dependencies(progress=progress)
            dependency_ready(force=True)
            return {"message": "Dependencies are installed and verified."}
        if action == "repair":
            control_center.stop_service(progress=progress)
            control_center.install_dependencies(repair=True, progress=progress)
            dependency_ready(force=True)
            return {
                "message": (
                    "Dependencies were rebuilt. Evidence and settings were preserved."
                )
            }
        if action == "start":
            state = control_center.start_service(open_browser=False, progress=progress)
            dependency_ready(force=True)
            return {"message": "Control Center started.", "url": state["url"]}
        if action == "stop":
            control_center.stop_service(progress=progress)
            return {"message": "Control Center stopped. Evidence was preserved."}
        if action == "restart":
            control_center.stop_service(progress=progress)
            state = control_center.start_service(
                open_browser=False,
                progress=progress,
            )
            dependency_ready(force=True)
            return {"message": "Control Center restarted.", "url": state["url"]}
        if action == "uninstall":
            control_center.stop_service(progress=progress)
            supervisor_setup.unregister_supervisor(
                ROOT,
                progress=progress,
                stop_running=False,
            )
            return {
                "message": (
                    "Supervisor registration was removed. The Control Center is "
                    "stopped; evidence and settings are preserved."
                ),
                "uninstall_ready": True,
            }
    raise control_center.ControlCenterError(f"Unsupported supervisor action: {action}")


def finish_uninstall(server: "SupervisorHTTPServer", job_id: str) -> None:
    time.sleep(2)
    add_progress(job_id, "Stopping the localhost supervisor.")
    server.shutdown()


def run_job(
    job_id: str,
    action: str,
    server: "SupervisorHTTPServer",
) -> None:
    global CURRENT_JOB_ID, LAST_ERROR
    with ACTION_LOCK:
        with JOBS_LOCK:
            job = JOBS[job_id]
            job["status"] = "running"
            job["started_at"] = utc_now()
            job["updated_at"] = job["started_at"]
        add_progress(job_id, f"{action.replace('_', ' ').title()} started.")
        try:
            result = execute_action(action, job_id)
        except Exception as exc:
            message = redact(str(exc) or exc.__class__.__name__)
            with JOBS_LOCK:
                job = JOBS[job_id]
                job["status"] = "failed"
                job["error"] = message
                job["completed_at"] = utc_now()
                job["updated_at"] = job["completed_at"]
                LAST_ERROR = message
                CURRENT_JOB_ID = None
            add_progress(job_id, f"Action failed: {message}")
            return
        with JOBS_LOCK:
            job = JOBS[job_id]
            job["status"] = "succeeded"
            job["result"] = result
            job["completed_at"] = utc_now()
            job["updated_at"] = job["completed_at"]
            LAST_ERROR = ""
            CURRENT_JOB_ID = None
        add_progress(job_id, result["message"])
        if action == "uninstall":
            threading.Thread(
                target=finish_uninstall,
                args=(server, job_id),
                daemon=True,
            ).start()


def begin_job(action: str, server: "SupervisorHTTPServer") -> dict:
    global CURRENT_JOB_ID, LAST_ERROR
    if action not in {"install", "repair", "start", "stop", "restart", "uninstall"}:
        raise ValueError("Unsupported action.")
    with JOBS_LOCK:
        if CURRENT_JOB_ID:
            active = JOBS.get(CURRENT_JOB_ID)
            if active and active.get("status") in {"queued", "running"}:
                raise RuntimeError("Another supervisor action is already running.")
        while len(JOBS) >= MAX_JOBS:
            oldest_job_id = next(iter(JOBS))
            JOBS.pop(oldest_job_id, None)
        job_id = uuid.uuid4().hex
        created_at = utc_now()
        job = {
            "id": job_id,
            "action": action,
            "status": "queued",
            "created_at": created_at,
            "started_at": None,
            "updated_at": created_at,
            "completed_at": None,
            "progress": [],
            "result": None,
            "error": None,
        }
        JOBS[job_id] = job
        CURRENT_JOB_ID = job_id
        LAST_ERROR = ""
    threading.Thread(
        target=run_job,
        args=(job_id, action, server),
        daemon=True,
    ).start()
    return public_job(job) or {}


class SupervisorHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False


class SupervisorHandler(BaseHTTPRequestHandler):
    server_version = "NutanixSTIGSupervisor/1.2"

    def log_message(self, format_string: str, *args: object) -> None:
        append_log(
            f"http {self.client_address[0]} "
            + (format_string % args)
        )

    def _security_headers(self) -> None:
        self.send_header("Cache-Control", "no-store")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "object-src 'none'; frame-ancestors 'none'; base-uri 'none'",
        )
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")

    def _json(self, status: int, body: dict) -> None:
        payload = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self._security_headers()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _error(self, status: int, detail: str) -> None:
        self._json(status, {"detail": detail})

    def _request_is_local(self) -> bool:
        try:
            if not ipaddress.ip_address(self.client_address[0]).is_loopback:
                return False
        except ValueError:
            return False
        host_header = self.headers.get("Host", "")
        try:
            hostname = urlsplit(f"//{host_header}").hostname
        except ValueError:
            return False
        return hostname in {"127.0.0.1", "localhost", "::1"}

    def _post_is_authorized(self) -> bool:
        if not secrets.compare_digest(
            self.headers.get("X-CSRF-Token", ""),
            CSRF_TOKEN,
        ):
            return False
        origin = self.headers.get("Origin")
        if origin and origin not in {
            supervisor_setup.SUPERVISOR_URL,
            f"http://localhost:{supervisor_setup.SUPERVISOR_PORT}",
        }:
            return False
        return True

    def _read_json(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ValueError("Invalid request length.") from exc
        if length < 0 or length > MAX_REQUEST_BYTES:
            raise ValueError("Request body is too large.")
        if not length:
            return {}
        try:
            value = json.loads(self.rfile.read(length).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("Request body must be valid JSON.") from exc
        if not isinstance(value, dict):
            raise ValueError("Request body must be a JSON object.")
        return value

    def do_GET(self) -> None:  # noqa: N802
        if not self._request_is_local():
            self._error(HTTPStatus.FORBIDDEN, "Local requests only.")
            return
        path = urlsplit(self.path).path
        if path == "/api/health":
            self._json(
                HTTPStatus.OK,
                {
                    "status": "ok",
                    "supervisor": True,
                    "local_only": True,
                    "instance_id": INSTANCE_ID,
                    "version": control_center.VERSION,
                },
            )
            return
        if path == "/api/bootstrap":
            self._json(
                HTTPStatus.OK,
                {
                    "csrf": CSRF_TOKEN,
                    "supervisor_url": supervisor_setup.SUPERVISOR_URL,
                    "status": status_snapshot(),
                },
            )
            return
        if path == "/api/status":
            self._json(HTTPStatus.OK, status_snapshot())
            return
        if path.startswith("/api/jobs/"):
            job_id = path.removeprefix("/api/jobs/")
            with JOBS_LOCK:
                job = public_job(JOBS.get(job_id))
            if not job:
                self._error(HTTPStatus.NOT_FOUND, "Supervisor job not found.")
            else:
                self._json(HTTPStatus.OK, job)
            return
        asset = ASSETS.get(path)
        if asset:
            file_name, content_type = asset
            try:
                payload = (ASSET_DIR / file_name).read_bytes()
            except OSError:
                self._error(HTTPStatus.INTERNAL_SERVER_ERROR, "Supervisor assets are missing.")
                return
            self.send_response(HTTPStatus.OK)
            self._security_headers()
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        self._error(HTTPStatus.NOT_FOUND, "Not found.")

    def do_POST(self) -> None:  # noqa: N802
        if not self._request_is_local():
            self._error(HTTPStatus.FORBIDDEN, "Local requests only.")
            return
        if not self._post_is_authorized():
            self._error(HTTPStatus.FORBIDDEN, "Request verification failed.")
            return
        path = urlsplit(self.path).path
        if not path.startswith("/api/actions/"):
            self._error(HTTPStatus.NOT_FOUND, "Not found.")
            return
        try:
            self._read_json()
            action = path.removeprefix("/api/actions/")
            job = begin_job(action, self.server)
        except ValueError as exc:
            self._error(HTTPStatus.BAD_REQUEST, str(exc))
            return
        except RuntimeError as exc:
            self._error(HTTPStatus.CONFLICT, str(exc))
            return
        self._json(HTTPStatus.ACCEPTED, job)


def _write_state() -> None:
    control_center.save_json(
        supervisor_setup.state_file(ROOT),
        {
            "version": control_center.VERSION,
            "pid": os.getpid(),
            "instance_id": INSTANCE_ID,
            "url": supervisor_setup.SUPERVISOR_URL,
            "started_at": utc_now(),
            "root": str(ROOT),
        },
    )


def _clear_own_state() -> None:
    path = supervisor_setup.state_file(ROOT)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        if value.get("instance_id") == INSTANCE_ID:
            path.unlink()
    except (OSError, ValueError):
        pass


def serve(port: int = supervisor_setup.SUPERVISOR_PORT) -> None:
    control_center.ensure_supported_python()
    control_center.ensure_layout()
    if not all((ASSET_DIR / asset[0]).is_file() for asset in ASSETS.values()):
        raise control_center.ControlCenterError("Supervisor web assets are incomplete.")
    server = SupervisorHTTPServer((supervisor_setup.SUPERVISOR_HOST, port), SupervisorHandler)
    actual_port = int(server.server_address[1])
    if actual_port != supervisor_setup.SUPERVISOR_PORT:
        raise control_center.ControlCenterError(
            "The installed supervisor must use fixed port "
            f"{supervisor_setup.SUPERVISOR_PORT}."
        )
    _write_state()
    append_log(
        f"Supervisor {control_center.VERSION} started at "
        f"{supervisor_setup.SUPERVISOR_URL} with pid {os.getpid()}."
    )

    def stop_handler(_signum: int, _frame: object) -> None:
        threading.Thread(target=server.shutdown, daemon=True).start()

    for signal_name in ("SIGINT", "SIGTERM"):
        signal_value = getattr(signal, signal_name, None)
        if signal_value is not None:
            try:
                signal.signal(signal_value, stop_handler)
            except (OSError, ValueError):
                pass
    try:
        server.serve_forever(poll_interval=0.25)
    finally:
        server.server_close()
        _clear_own_state()
        append_log("Supervisor stopped.")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Serve the Nutanix STIG Control Center localhost supervisor."
    )
    parser.add_argument(
        "--port",
        type=int,
        default=supervisor_setup.SUPERVISOR_PORT,
        help=argparse.SUPPRESS,
    )
    args = parser.parse_args()
    try:
        serve(args.port)
        return 0
    except (OSError, control_center.ControlCenterError) as exc:
        append_log(f"Supervisor failed: {exc}")
        print(f"Supervisor error: {exc}", file=os.sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
