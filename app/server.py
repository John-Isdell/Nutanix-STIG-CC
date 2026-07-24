#!/usr/bin/env python3
"""Local-only web control plane for the verified Nutanix STIG hardening engine."""

from __future__ import annotations

import argparse
import base64
import configparser
import hashlib
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import threading
import uuid
import zipfile
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

import httpx
import paramiko
from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from core.nutanix_stig_harden import MANUAL_CONTROLS, PROFILE_NOTES, PROFILES


APP_DIR = Path(__file__).resolve().parent
STATIC_DIR = APP_DIR / "static"
DOCS_DIR = APP_DIR / "docs"
DATA_DIR = APP_DIR / "data"
RUNS_DIR = DATA_DIR / "runs"
KNOWN_HOSTS = DATA_DIR / "known_hosts"
STATE_FILE = DATA_DIR / "state.json"
AUDIT_FILE = DATA_DIR / "audit.json"
ENGINE = APP_DIR / "core" / "nutanix_stig_harden.py"

for directory in (DATA_DIR, RUNS_DIR):
    directory.mkdir(parents=True, exist_ok=True)
KNOWN_HOSTS.touch(mode=0o600, exist_ok=True)

app = FastAPI(
    title="Nutanix STIG Control Center",
    version="1.2.0",
    docs_url=None,
    redoc_url=None,
    openapi_url="/api/openapi.json",
)
app.mount("/assets", StaticFiles(directory=STATIC_DIR), name="assets")

state_lock = threading.RLock()
operation_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="stig-operation")
sessions: dict[str, dict[str, Any]] = {}
jobs: dict[str, dict[str, Any]] = {}
pending_host_keys: dict[str, dict[str, Any]] = {}
current_job_id: str | None = None
INSTANCE_ID = "unmanaged"

HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$")
SAFE_TEXT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/ -]{0,127}$")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def load_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return default


def save_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2), encoding="utf-8")
    os.replace(temporary, path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def validate_host(value: str, label: str = "host") -> str:
    value = value.strip()
    if not value:
        raise HTTPException(422, f"{label} is required")
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        if not HOST_RE.fullmatch(value) or ".." in value:
            raise HTTPException(422, f"{label} is not a valid IP address or DNS name")
        return value


def validate_port(value: int, label: str = "port") -> int:
    if not 1 <= value <= 65535:
        raise HTTPException(422, f"{label} must be between 1 and 65535")
    return value


def safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", value)[:80] or "item"


def sanitize_config(payload: dict[str, Any]) -> dict[str, Any]:
    secret_keys = {
        "password",
        "private_key",
        "key_passphrase",
        "pc_password",
        "pc_private_key",
        "pc_key_passphrase",
        "api_password",
        "api_ca_pem",
        "typed_confirmation",
        "approval_id",
        "ack_backup",
        "ack_window",
        "ack_authorized",
        "source_job_id",
        "manifest_name",
        "apply_rollback",
    }
    cleaned = {key: value for key, value in payload.items() if key not in secret_keys}
    cleaned["credentials_saved"] = False
    return cleaned


def config_fingerprint(payload: dict[str, Any]) -> str:
    relevant = sanitize_config(payload)
    relevant.pop("credentials_saved", None)
    relevant.pop("typed_confirmation", None)
    relevant.pop("approval_id", None)
    relevant.pop("ack_backup", None)
    relevant.pop("ack_window", None)
    relevant.pop("ack_authorized", None)
    relevant.pop("apply_rollback", None)
    encoded = json.dumps(relevant, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def active_state() -> dict[str, Any]:
    return load_json(
        STATE_FILE,
        {
            "active_cluster": None,
            "latest_dry_run": None,
            "latest_rollback_preview": None,
            "manual_controls": {},
        },
    )


def write_state(value: dict[str, Any]) -> None:
    save_json(STATE_FILE, value)


def active_host() -> str | None:
    state = active_state()
    cluster = state.get("active_cluster") or {}
    return cluster.get("cluster_host")


def ensure_active_context(payload: dict[str, Any]) -> dict[str, Any]:
    host = validate_host(str(payload.get("cluster_host", "")), "Cluster address")
    state = active_state()
    active = state.get("active_cluster")
    if active and active.get("cluster_host") != host:
        raise HTTPException(
            409,
            "A different cluster workspace is active. Export its evidence and use "
            "Close workspace before connecting to another cluster.",
        )
    sanitized = sanitize_config(payload)
    sanitized["cluster_host"] = host
    sanitized["updated_at"] = utc_now()
    state["active_cluster"] = sanitized
    write_state(state)
    return state


def get_session(request: Request) -> tuple[str, dict[str, Any]]:
    sid = request.cookies.get("stig_session", "")
    session = sessions.get(sid)
    if not sid or not session:
        raise HTTPException(401, "Local session expired. Refresh the page.")
    return sid, session


def require_csrf(
    request: Request, x_csrf_token: str = Header(default="", alias="X-CSRF-Token")
) -> tuple[str, dict[str, Any]]:
    sid, session = get_session(request)
    if not secrets.compare_digest(x_csrf_token, str(session.get("csrf", ""))):
        raise HTTPException(403, "Invalid request token. Refresh the page.")
    return sid, session


@app.middleware("http")
async def local_security_middleware(request: Request, call_next):
    raw_host = request.headers.get("host", "").lower()
    if raw_host.startswith("[") and "]" in raw_host:
        host_header = raw_host[1 : raw_host.index("]")]
    elif raw_host.count(":") == 1:
        host_header = raw_host.split(":", 1)[0]
    else:
        host_header = raw_host
    if host_header not in {"127.0.0.1", "localhost", "::1"}:
        return Response("Local access only", status_code=403)
    origin = request.headers.get("origin")
    if origin and not re.fullmatch(r"https?://(127\.0\.0\.1|localhost|\[::1\])(?::\d+)?", origin):
        return Response("Cross-origin request blocked", status_code=403)
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
    )
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    return response


class HostKeyInspect(BaseModel):
    host: str
    port: int = Field(default=22, ge=1, le=65535)


class HostKeyTrust(BaseModel):
    host: str
    port: int = Field(default=22, ge=1, le=65535)
    fingerprint: str
    verification_suffix: str


class ClusterPayload(BaseModel):
    cluster_host: str
    ssh_port: int = Field(default=22, ge=1, le=65535)
    username: str = "nutanix"
    auth_method: Literal["password", "key"] = "password"
    password: str = ""
    private_key: str = ""
    key_passphrase: str = ""
    pc_host: str = ""
    pc_port: int = Field(default=22, ge=1, le=65535)
    pc_username: str = "nutanix"
    pc_use_same_auth: bool = True
    pc_auth_method: Literal["password", "key"] = "password"
    pc_password: str = ""
    pc_private_key: str = ""
    pc_key_passphrase: str = ""
    profile: Literal["REPORT_ONLY", "STIG_STANDARD", "STIG_HIGH", "DODIN_APL"] = (
        "STIG_STANDARD"
    )
    scopes: list[Literal["cvm", "ahv", "pcvm"]] = ["cvm", "ahv"]
    full_health_check: bool = True
    command_timeout: int = Field(default=300, ge=30, le=3600)
    verification_timeout: int = Field(default=120, ge=0, le=1800)
    verification_interval: int = Field(default=10, ge=1, le=120)
    min_name_servers: int = Field(default=2, ge=1, le=10)
    min_ntp_servers: int = Field(default=2, ge=1, le=10)
    syslog_enabled: bool = False
    syslog_server_name: str = "SIEM01"
    syslog_server_ip: str = ""
    syslog_port: int = Field(default=514, ge=1, le=65535)
    syslog_protocol: Literal["tcp", "udp"] = "tcp"
    syslog_relp: bool = True
    syslog_modules: str = "AUDIT,API_AUDIT,PRISM"
    api_enabled: bool = False
    api_host: str = ""
    api_port: int = Field(default=9440, ge=1, le=65535)
    api_username: str = ""
    api_password: str = ""
    api_ca_pem: str = ""
    api_cluster_ext_id: str = ""


class ApplyPayload(ClusterPayload):
    approval_id: str
    typed_confirmation: str
    ack_backup: bool = False
    ack_window: bool = False
    ack_authorized: bool = False


class ContextClose(BaseModel):
    confirmation: str


class ManualUpdate(BaseModel):
    index: int = Field(ge=0)
    status: Literal["not_started", "in_progress", "complete", "accepted_risk"]
    note: str = Field(default="", max_length=1000)


class V4Payload(BaseModel):
    api_host: str
    api_port: int = Field(default=9440, ge=1, le=65535)
    api_username: str
    api_password: str
    api_ca_pem: str = ""


class RollbackPayload(ClusterPayload):
    source_job_id: str
    manifest_name: str
    apply_rollback: bool = False
    approval_id: str = ""
    typed_confirmation: str = ""
    ack_backup: bool = False
    ack_window: bool = False
    ack_authorized: bool = False


def model_data(model: BaseModel) -> dict[str, Any]:
    return model.model_dump() if hasattr(model, "model_dump") else model.dict()


@app.get("/")
def home() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/bootstrap")
def bootstrap(request: Request, response: Response) -> dict[str, Any]:
    sid = request.cookies.get("stig_session")
    if not sid or sid not in sessions:
        sid = secrets.token_urlsafe(32)
        sessions[sid] = {"csrf": secrets.token_urlsafe(32), "created_at": utc_now()}
    response.set_cookie(
        "stig_session",
        sid,
        httponly=True,
        secure=False,
        samesite="strict",
        path="/",
    )
    state = active_state()
    return {
        "csrf": sessions[sid]["csrf"],
        "version": "1.2.0",
        "active_cluster": state.get("active_cluster"),
        "latest_dry_run": state.get("latest_dry_run"),
        "profiles": [
            {"id": name, "note": PROFILE_NOTES[name], "parameters": len(PROFILES[name])}
            for name in ("REPORT_ONLY", "STIG_STANDARD", "STIG_HIGH", "DODIN_APL")
        ],
        "known_hosts_file": str(KNOWN_HOSTS),
        "local_only": True,
    }


@app.get("/api/health")
def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "instance_id": INSTANCE_ID,
        "local_only": True,
        "active_cluster": active_host(),
        "operation_running": bool(current_job_id and jobs.get(current_job_id, {}).get("status") == "running"),
    }


@app.post("/api/host-key/inspect")
def inspect_host_key(
    payload: HostKeyInspect,
    session_info: tuple[str, dict[str, Any]] = Depends(require_csrf),
) -> dict[str, Any]:
    sid, _ = session_info
    host = validate_host(payload.host)
    port = validate_port(payload.port)
    transport: paramiko.Transport | None = None
    try:
        sock = socket.create_connection((host, port), timeout=10)
        transport = paramiko.Transport(sock)
        transport.start_client(timeout=10)
        key = transport.get_remote_server_key()
    except (OSError, paramiko.SSHException) as exc:
        raise HTTPException(502, f"Could not read the SSH host key: {exc}") from exc
    finally:
        if transport:
            transport.close()
    digest = base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")
    fingerprint = f"SHA256:{digest}"
    pending_host_keys[sid] = {
        "host": host,
        "port": port,
        "fingerprint": fingerprint,
        "key": key,
        "created_at": utc_now(),
    }
    return {
        "host": host,
        "port": port,
        "algorithm": key.get_name(),
        "bits": key.get_bits(),
        "fingerprint": fingerprint,
        "verification_suffix": fingerprint[-12:],
        "instruction": (
            "Compare this fingerprint with a value obtained from the Nutanix console "
            "or another trusted channel before trusting it."
        ),
    }


@app.post("/api/host-key/trust")
def trust_host_key(
    payload: HostKeyTrust,
    session_info: tuple[str, dict[str, Any]] = Depends(require_csrf),
) -> dict[str, Any]:
    sid, _ = session_info
    pending = pending_host_keys.get(sid)
    host = validate_host(payload.host)
    if (
        not pending
        or pending["host"] != host
        or pending["port"] != payload.port
        or pending["fingerprint"] != payload.fingerprint
    ):
        raise HTTPException(409, "Inspect this host key again before trusting it.")
    expected_suffix = pending["fingerprint"][-12:]
    if not secrets.compare_digest(payload.verification_suffix.strip(), expected_suffix):
        raise HTTPException(422, "The fingerprint verification suffix does not match.")
    host_keys = paramiko.HostKeys()
    try:
        host_keys.load(str(KNOWN_HOSTS))
    except (OSError, ValueError):
        pass
    lookup_name = host if payload.port == 22 else f"[{host}]:{payload.port}"
    host_keys.add(lookup_name, pending["key"].get_name(), pending["key"])
    host_keys.save(str(KNOWN_HOSTS))
    pending_host_keys.pop(sid, None)
    return {"trusted": True, "host": host, "fingerprint": payload.fingerprint}


def temporary_private_key(
    payload: dict[str, Any], directory: Path, field_prefix: str = ""
) -> Path | None:
    method_field = f"{field_prefix}auth_method"
    key_field = f"{field_prefix}private_key"
    if payload.get(method_field) != "key":
        return None
    private_key = str(payload.get(key_field, "")).strip()
    if not private_key:
        raise HTTPException(422, "Select or paste an SSH private key.")
    path = directory / f".operation_{field_prefix or 'cluster_'}key"
    path.write_text(private_key + "\n", encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return path


def open_ssh(payload: dict[str, Any], timeout: int = 30) -> paramiko.SSHClient:
    host = validate_host(str(payload.get("cluster_host", "")), "Cluster address")
    port = validate_port(int(payload.get("ssh_port", 22)), "SSH port")
    username = str(payload.get("username", "")).strip()
    if not username or len(username) > 128:
        raise HTTPException(422, "A valid SSH username is required.")
    temp_dir = DATA_DIR / ".connection-test"
    temp_dir.mkdir(parents=True, exist_ok=True)
    key_path: Path | None = None
    try:
        key_path = temporary_private_key(payload, temp_dir)
        client = paramiko.SSHClient()
        client.load_host_keys(str(KNOWN_HOSTS))
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        kwargs: dict[str, Any] = {
            "hostname": host,
            "port": port,
            "username": username,
            "timeout": timeout,
            "banner_timeout": timeout,
            "auth_timeout": timeout,
            "allow_agent": False,
            "look_for_keys": False,
        }
        if key_path:
            kwargs["key_filename"] = str(key_path)
            kwargs["passphrase"] = payload.get("key_passphrase") or None
        else:
            if not payload.get("password"):
                raise HTTPException(422, "Enter the SSH password.")
            kwargs["password"] = payload["password"]
        client.connect(**kwargs)
        return client
    except paramiko.BadHostKeyException as exc:
        raise HTTPException(409, f"SSH host key changed: {exc}") from exc
    except (paramiko.AuthenticationException, paramiko.SSHException, OSError) as exc:
        raise HTTPException(502, f"SSH connection failed: {exc}") from exc
    finally:
        if key_path:
            key_path.unlink(missing_ok=True)


@app.post("/api/connection/test")
def test_connection(
    payload: ClusterPayload,
    _: tuple[str, dict[str, Any]] = Depends(require_csrf),
) -> dict[str, Any]:
    data = model_data(payload)
    client = open_ssh(data)
    try:
        _, stdout, stderr = client.exec_command(
            "bash -lc 'ncli cluster info'", timeout=min(data["command_timeout"], 60)
        )
        output = stdout.read().decode("utf-8", errors="replace")
        error = stderr.read().decode("utf-8", errors="replace")
        status = stdout.channel.recv_exit_status()
        if status != 0:
            raise HTTPException(502, f"Connected, but ncli cluster info failed: {error[:400]}")
        cluster_name = ""
        for line in output.splitlines():
            if re.match(r"\s*(Cluster Name|Name)\s*:", line, re.I):
                cluster_name = line.split(":", 1)[1].strip()[:160]
                break
        return {
            "connected": True,
            "cluster_host": data["cluster_host"],
            "cluster_name": cluster_name or "Connected cluster",
            "ncli_available": True,
            "credentials_saved": False,
        }
    finally:
        client.close()


@app.post("/api/v4/cluster-identity")
def v4_cluster_identity(
    payload: V4Payload,
    _: tuple[str, dict[str, Any]] = Depends(require_csrf),
) -> dict[str, Any]:
    host = validate_host(payload.api_host, "Prism API address")
    if not payload.api_username or not payload.api_password:
        raise HTTPException(422, "Prism API username and password are required.")
    ca_path: Path | None = None
    verify: str | bool = True
    try:
        if payload.api_ca_pem.strip():
            ca_path = DATA_DIR / ".api_ca.pem"
            ca_path.write_text(payload.api_ca_pem.strip() + "\n", encoding="utf-8")
            verify = str(ca_path)
        url = f"https://{host}:{payload.api_port}/api/clustermgmt/v4.2/config/clusters"
        with httpx.Client(
            verify=verify,
            timeout=30,
            auth=(payload.api_username, payload.api_password),
            follow_redirects=False,
        ) as client:
            response = client.get(url, params={"$limit": 100})
        if response.status_code >= 400:
            raise HTTPException(
                502,
                f"Nutanix v4 API returned HTTP {response.status_code}. "
                "Check the Prism address, credentials, permissions, and AOS/PC version.",
            )
        body = response.json()
        clusters = body.get("data") if isinstance(body, dict) else None
        if not isinstance(clusters, list):
            raise HTTPException(502, "The v4 response did not contain a cluster list.")
        inventory = []
        for item in clusters[:100]:
            if not isinstance(item, dict):
                continue
            network = item.get("network") or {}
            inventory.append(
                {
                    "name": item.get("name") or item.get("clusterName") or "Unnamed cluster",
                    "ext_id": item.get("extId") or item.get("ext_id") or "",
                    "type": item.get("clusterFunction") or item.get("clusterType") or "",
                    "version": item.get("config") or item.get("version") or "",
                    "external_address": network.get("externalAddress")
                    if isinstance(network, dict)
                    else "",
                }
            )
        return {
            "verified": True,
            "api": "Nutanix Cluster Management v4.2",
            "endpoint": f"https://{host}:{payload.api_port}",
            "clusters": inventory,
            "read_only": True,
            "note": (
                "The Control Center uses v4 here for identity and inventory only. "
                "Security-parameter changes remain on the verified SSH/nCLI path."
            ),
        }
    except (httpx.HTTPError, ValueError) as exc:
        raise HTTPException(502, f"Nutanix v4 API validation failed: {exc}") from exc
    finally:
        if ca_path:
            ca_path.unlink(missing_ok=True)


@app.post("/api/configuration/activate")
def activate_configuration(
    payload: ClusterPayload,
    _: tuple[str, dict[str, Any]] = Depends(require_csrf),
) -> dict[str, Any]:
    data = model_data(payload)
    state = ensure_active_context(data)
    return {
        "active_cluster": state["active_cluster"],
        "fingerprint": config_fingerprint(data),
        "credentials_saved": False,
    }


def validate_operation_payload(data: dict[str, Any]) -> None:
    validate_host(str(data.get("cluster_host", "")), "Cluster address")
    validate_port(int(data.get("ssh_port", 22)), "SSH port")
    scopes = data.get("scopes") or []
    if not scopes:
        raise HTTPException(422, "Select at least one hardening scope.")
    if "pcvm" in scopes and not str(data.get("pc_host", "")).strip():
        raise HTTPException(422, "A Prism Central address is required for the PCVM scope.")
    if data.get("syslog_enabled"):
        try:
            ipaddress.ip_address(str(data.get("syslog_server_ip", "")))
        except ValueError as exc:
            raise HTTPException(422, "Syslog server must be a valid IP address.") from exc
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", str(data.get("syslog_server_name", ""))):
            raise HTTPException(422, "Syslog server name contains unsupported characters.")
    if data.get("api_enabled") and not str(data.get("api_cluster_ext_id", "")).strip():
        raise HTTPException(
            422,
            "Verify the Nutanix v4 identity and select the one active cluster.",
        )
    if data.get("auth_method") == "key":
        if not str(data.get("private_key", "")).strip():
            raise HTTPException(422, "Select or paste an SSH private key.")
    elif not str(data.get("password", "")):
        raise HTTPException(422, "Enter the SSH password.")
    if "pcvm" in scopes and not data.get("pc_use_same_auth", True):
        if data.get("pc_auth_method") == "key":
            if not str(data.get("pc_private_key", "")).strip():
                raise HTTPException(422, "Select or paste the PCVM SSH private key.")
        elif not str(data.get("pc_password", "")):
            raise HTTPException(422, "Enter the PCVM SSH password.")


def build_engine_config(
    data: dict[str, Any],
    path: Path,
    key_path: Path | None,
    pc_key_path: Path | None,
) -> None:
    cfg = configparser.ConfigParser()
    cfg["cluster"] = {
        "host": data["cluster_host"],
        "username": data["username"],
        "ssh_key_file": str(key_path or ""),
        "ssh_key_passphrase": data.get("key_passphrase", ""),
        "password": "",
        "port": str(data["ssh_port"]),
    }
    cfg["prism_central"] = {
        "host": data.get("pc_host", ""),
        "username": data.get("pc_username") or data["username"],
        "ssh_key_file": str(pc_key_path or ""),
        "ssh_key_passphrase": (
            data.get("key_passphrase", "")
            if data.get("pc_use_same_auth", True)
            else data.get("pc_key_passphrase", "")
        ),
        "password": "",
        "port": str(data.get("pc_port", 22)),
    }
    cfg["options"] = {
        "profile": data["profile"],
        "scopes": ",".join(data["scopes"]),
        "log_retention_days": "3650",
        "command_timeout": str(data["command_timeout"]),
        "verification_timeout": str(data["verification_timeout"]),
        "verification_interval": str(data["verification_interval"]),
        "ncli_path": "",
        "host_key_policy": "reject",
        "known_hosts_file": str(KNOWN_HOSTS),
        "full_health_check": "true" if data["full_health_check"] else "false",
        "min_name_servers": str(data["min_name_servers"]),
        "min_ntp_servers": str(data["min_ntp_servers"]),
    }
    cfg["syslog"] = {
        "enabled": "true" if data["syslog_enabled"] else "false",
        "server_name": data["syslog_server_name"],
        "server_ip": data["syslog_server_ip"],
        "port": str(data["syslog_port"]),
        "protocol": data["syslog_protocol"],
        "relp_enabled": "true" if data["syslog_relp"] else "false",
        "modules": data["syslog_modules"],
    }
    cfg["email"] = {"enabled": "false"}
    with path.open("w", encoding="utf-8") as handle:
        cfg.write(handle)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def report_preflight_ok(report: dict[str, Any]) -> bool:
    results = report.get("results") or {}
    targets = results.get("targets") or []
    return bool(targets) and all(target.get("preflight") == "PASS" for target in targets)


def summarized_report(report: dict[str, Any] | None) -> dict[str, Any]:
    if not report:
        return {}
    targets = []
    for target in (report.get("results") or {}).get("targets", []):
        targets.append(
            {
                "host": target.get("host"),
                "type": target.get("type"),
                "preflight": target.get("preflight"),
                "findings": target.get("findings") or [],
                "scopes": target.get("scopes") or {},
                "lockdown_ready": target.get("lockdown_ready"),
                "syslog_failures": target.get("syslog_failures"),
            }
        )
    return {
        "run_id": report.get("run_id"),
        "mode": report.get("mode"),
        "profile": report.get("profile"),
        "approval_id": report.get("approval_id"),
        "targets": targets,
        "manual_controls_remaining": report.get("manual_controls_remaining") or [],
        "fatal_error": (report.get("results") or {}).get("fatal_error"),
    }


def append_audit(entry: dict[str, Any]) -> None:
    audit = load_json(AUDIT_FILE, [])
    audit.append(entry)
    save_json(AUDIT_FILE, audit[-500:])


def evidence_zip(job_dir: Path, job_id: str) -> Path:
    archive = job_dir / f"nutanix_stig_evidence_{job_id}.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        for item in job_dir.rglob("*"):
            if not item.is_file() or item == archive or item.name.startswith(".operation"):
                continue
            bundle.write(item, item.relative_to(job_dir))
        if STATE_FILE.exists():
            bundle.writestr("control-center/active-state-snapshot.json", STATE_FILE.read_text("utf-8"))
        bundle.write(
            DOCS_DIR / "Nutanix_STIG_Script_Verification_Report.md",
            "documentation/Nutanix_STIG_Script_Verification_Report.md",
        )
    return archive


def find_report(job_dir: Path) -> tuple[Path | None, dict[str, Any] | None]:
    reports = sorted((job_dir / "reports").glob("stig_report_*.json"))
    if not reports:
        return None, None
    path = reports[-1]
    try:
        return path, json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return path, None


def run_engine_job(
    job_id: str,
    data: dict[str, Any],
    mode: Literal["DRY_RUN", "APPLY", "ROLLBACK_PREVIEW", "ROLLBACK_APPLY"],
    rollback_manifest: Path | None = None,
) -> None:
    global current_job_id
    job_dir = RUNS_DIR / job_id
    job_dir.mkdir(parents=True, exist_ok=True)
    config_path = job_dir / ".operation.ini"
    key_path: Path | None = None
    console_path = job_dir / "console.log"
    sanitized = sanitize_config(data)
    sanitized.update(
        {
            "job_id": job_id,
            "mode": mode,
            "configuration_fingerprint": config_fingerprint(data),
            "started_at": utc_now(),
        }
    )
    save_json(job_dir / "operation.json", sanitized)
    return_code = 99
    failure = ""
    pc_key_path: Path | None = None
    try:
        key_path = temporary_private_key(data, job_dir)
        if data.get("pc_use_same_auth", True):
            pc_key_path = key_path
        else:
            pc_key_path = temporary_private_key(data, job_dir, "pc_")
        build_engine_config(data, config_path, key_path, pc_key_path)
        command = [
            sys.executable,
            str(ENGINE),
            "--config",
            str(config_path),
            "--profile",
            data["profile"],
            "--scopes",
            ",".join(data["scopes"]),
            "--non-interactive",
            "--no-email",
        ]
        if data["full_health_check"]:
            command.append("--full-health-check")
        if rollback_manifest:
            command.extend(["--rollback", str(rollback_manifest)])
        if mode in {"APPLY", "ROLLBACK_APPLY"}:
            command.extend(["--apply", "--approval-id", data["approval_id"]])
        environment = os.environ.copy()
        environment["NTNX_STIG_DATA_DIR"] = str(job_dir)
        environment["NTNX_STIG_CLUSTER_USER"] = data["username"]
        if data.get("auth_method") == "password":
            environment["NTNX_STIG_CLUSTER_PASSWORD"] = data["password"]
        if key_path:
            environment["NTNX_STIG_CLUSTER_KEYFILE"] = str(key_path)
        environment["NTNX_STIG_PC_USER"] = data.get("pc_username") or data["username"]
        if data.get("pc_use_same_auth", True):
            if data.get("auth_method") == "password":
                environment["NTNX_STIG_PC_PASSWORD"] = data["password"]
            if key_path:
                environment["NTNX_STIG_PC_KEYFILE"] = str(key_path)
        else:
            if data.get("pc_auth_method") == "password":
                environment["NTNX_STIG_PC_PASSWORD"] = data.get("pc_password", "")
            if pc_key_path:
                environment["NTNX_STIG_PC_KEYFILE"] = str(pc_key_path)
        with console_path.open("w", encoding="utf-8") as console:
            process = subprocess.run(
                command,
                cwd=APP_DIR,
                env=environment,
                stdout=console,
                stderr=subprocess.STDOUT,
                text=True,
                check=False,
            )
            return_code = process.returncode
    except Exception as exc:  # noqa: BLE001 - capture in local audit, never hide it
        failure = f"{type(exc).__name__}: {exc}"
        console_path.write_text(failure + "\n", encoding="utf-8")
    finally:
        config_path.unlink(missing_ok=True)
        if key_path:
            key_path.unlink(missing_ok=True)
        if pc_key_path and pc_key_path != key_path:
            pc_key_path.unlink(missing_ok=True)
        for secret_key in (
            "password",
            "private_key",
            "key_passphrase",
            "pc_password",
            "pc_private_key",
            "pc_key_passphrase",
            "api_password",
            "api_ca_pem",
        ):
            data[secret_key] = ""

    report_path, report = find_report(job_dir)
    completed_at = utc_now()
    operation_status = "succeeded" if return_code == 0 else "failed"
    archive = evidence_zip(job_dir, job_id)
    rollback_files = [
        str(path.name) for path in sorted((job_dir / "rollback").glob("*.json"))
    ]
    job_summary = {
        "id": job_id,
        "status": operation_status,
        "mode": mode,
        "cluster_host": sanitized["cluster_host"],
        "profile": sanitized["profile"],
        "scopes": sanitized["scopes"],
        "full_health_check": sanitized["full_health_check"],
        "configuration_fingerprint": sanitized["configuration_fingerprint"],
        "started_at": sanitized["started_at"],
        "completed_at": completed_at,
        "return_code": return_code,
        "failure": failure,
        "report": summarized_report(report),
        "report_file": report_path.name if report_path else None,
        "evidence_file": archive.name,
        "rollback_manifests": rollback_files,
    }
    if rollback_manifest:
        job_summary["source_job_id"] = data.get("source_job_id")
        job_summary["manifest_name"] = data.get("manifest_name")
    save_json(job_dir / "job-summary.json", job_summary)
    append_audit(job_summary)
    with state_lock:
        jobs[job_id] = job_summary
        state = active_state()
        if mode == "DRY_RUN":
            if (
                return_code == 0
                and report_preflight_ok(report or {})
                and sanitized["full_health_check"]
                and sanitized["profile"] != "REPORT_ONLY"
            ):
                state["latest_dry_run"] = {
                    "job_id": job_id,
                    "configuration_fingerprint": sanitized["configuration_fingerprint"],
                    "cluster_host": sanitized["cluster_host"],
                    "completed_at": completed_at,
                    "apply_ready": True,
                }
            else:
                state["latest_dry_run"] = {
                    "job_id": job_id,
                    "configuration_fingerprint": sanitized["configuration_fingerprint"],
                    "cluster_host": sanitized["cluster_host"],
                    "completed_at": completed_at,
                    "apply_ready": False,
                    "reason": (
                        "Apply requires a successful full-health dry run, passing preflight, "
                        "and a change-capable profile."
                    ),
                }
        elif mode == "ROLLBACK_PREVIEW":
            state["latest_rollback_preview"] = {
                "job_id": job_id,
                "source_job_id": data.get("source_job_id"),
                "manifest_name": data.get("manifest_name"),
                "configuration_fingerprint": sanitized["configuration_fingerprint"],
                "ready": return_code == 0,
            }
        write_state(state)
        current_job_id = None


def begin_job(
    data: dict[str, Any],
    mode: Literal["DRY_RUN", "APPLY", "ROLLBACK_PREVIEW", "ROLLBACK_APPLY"],
    rollback_manifest: Path | None = None,
) -> dict[str, Any]:
    global current_job_id
    validate_operation_payload(data)
    ensure_active_context(data)
    with state_lock:
        if current_job_id and jobs.get(current_job_id, {}).get("status") == "running":
            raise HTTPException(409, "Another cluster operation is already running.")
        job_id = uuid.uuid4().hex[:16]
        summary = {
            "id": job_id,
            "status": "running",
            "mode": mode,
            "cluster_host": data["cluster_host"],
            "profile": data["profile"],
            "scopes": data["scopes"],
            "started_at": utc_now(),
            "configuration_fingerprint": config_fingerprint(data),
        }
        jobs[job_id] = summary
        current_job_id = job_id
        operation_executor.submit(run_engine_job, job_id, data, mode, rollback_manifest)
    return summary


@app.post("/api/operations/dry-run")
def start_dry_run(
    payload: ClusterPayload,
    _: tuple[str, dict[str, Any]] = Depends(require_csrf),
) -> dict[str, Any]:
    data = model_data(payload)
    if not data["full_health_check"]:
        # A quick assessment is useful, but it cannot authorize Apply.
        pass
    return begin_job(data, "DRY_RUN")


def validate_authorization(data: dict[str, Any], action: str) -> None:
    expected = f"{action} {data['cluster_host']}"
    if not secrets.compare_digest(str(data.get("typed_confirmation", "")), expected):
        raise HTTPException(422, f"Type exactly: {expected}")
    if not all(data.get(key) for key in ("ack_backup", "ack_window", "ack_authorized")):
        raise HTTPException(422, "Complete all Apply acknowledgements.")
    approval_id = str(data.get("approval_id", "")).strip()
    if not SAFE_TEXT_RE.fullmatch(approval_id):
        raise HTTPException(422, "Enter a valid change or approval ID.")


def validate_apply(data: dict[str, Any]) -> None:
    state = active_state()
    dry_run = state.get("latest_dry_run") or {}
    if not dry_run.get("apply_ready"):
        raise HTTPException(409, "Run a successful full-health dry run before Apply.")
    if dry_run.get("configuration_fingerprint") != config_fingerprint(data):
        raise HTTPException(
            409,
            "The configuration changed after the dry run. Run dry run again before Apply.",
        )
    validate_authorization(data, "APPLY")


@app.post("/api/operations/apply")
def start_apply(
    payload: ApplyPayload,
    _: tuple[str, dict[str, Any]] = Depends(require_csrf),
) -> dict[str, Any]:
    data = model_data(payload)
    validate_apply(data)
    return begin_job(data, "APPLY")


def resolve_manifest(source_job_id: str, manifest_name: str) -> Path:
    if not re.fullmatch(r"[a-f0-9]{16}", source_job_id):
        raise HTTPException(422, "Invalid source job.")
    if Path(manifest_name).name != manifest_name:
        raise HTTPException(422, "Invalid manifest name.")
    path = (RUNS_DIR / source_job_id / "rollback" / manifest_name).resolve()
    expected_root = (RUNS_DIR / source_job_id / "rollback").resolve()
    if expected_root not in path.parents or not path.is_file():
        raise HTTPException(404, "Rollback manifest not found.")
    return path


@app.post("/api/operations/rollback")
def start_rollback(
    payload: RollbackPayload,
    _: tuple[str, dict[str, Any]] = Depends(require_csrf),
) -> dict[str, Any]:
    data = model_data(payload)
    manifest = resolve_manifest(data["source_job_id"], data["manifest_name"])
    if data["apply_rollback"]:
        preview = (active_state().get("latest_rollback_preview") or {})
        if (
            not preview.get("ready")
            or preview.get("source_job_id") != data["source_job_id"]
            or preview.get("manifest_name") != data["manifest_name"]
            or preview.get("configuration_fingerprint") != config_fingerprint(data)
        ):
            raise HTTPException(409, "Preview this exact rollback before applying it.")
        validate_authorization(data, "ROLLBACK")
        return begin_job(data, "ROLLBACK_APPLY", manifest)
    return begin_job(data, "ROLLBACK_PREVIEW", manifest)


def load_job(job_id: str) -> dict[str, Any]:
    with state_lock:
        job = jobs.get(job_id)
    if job:
        return job
    summary_file = RUNS_DIR / safe_name(job_id) / "job-summary.json"
    if summary_file.is_file():
        return load_json(summary_file, {})
    raise HTTPException(404, "Operation not found.")


@app.get("/api/jobs/{job_id}")
def job_status(job_id: str, request: Request) -> dict[str, Any]:
    get_session(request)
    job = load_job(job_id)
    if active_host() and job.get("cluster_host") != active_host():
        raise HTTPException(403, "This operation belongs to an archived cluster workspace.")
    if job.get("status") == "running":
        console_file = RUNS_DIR / job_id / "console.log"
        tail = ""
        if console_file.is_file():
            try:
                tail = console_file.read_text(encoding="utf-8", errors="replace")[-6000:]
            except OSError:
                pass
        job = {**job, "console_tail": tail}
    return job


@app.get("/api/jobs/{job_id}/evidence")
def download_evidence(job_id: str, request: Request) -> FileResponse:
    get_session(request)
    job = load_job(job_id)
    archive = RUNS_DIR / job_id / str(job.get("evidence_file", ""))
    if not archive.is_file():
        raise HTTPException(404, "Evidence package is not ready.")
    return FileResponse(
        archive,
        media_type="application/zip",
        filename=f"nutanix-stig-{job.get('cluster_host', 'cluster')}-{job_id}.zip",
    )


@app.get("/api/audit")
def audit(request: Request) -> dict[str, Any]:
    get_session(request)
    host = active_host()
    entries = load_json(AUDIT_FILE, [])
    if host:
        entries = [item for item in entries if item.get("cluster_host") == host]
    return {"active_cluster": host, "entries": list(reversed(entries[-100:]))}


@app.get("/api/manual-controls")
def manual_controls(request: Request) -> dict[str, Any]:
    get_session(request)
    state = active_state()
    tracked = state.get("manual_controls") or {}
    controls = []
    for index, text in enumerate(MANUAL_CONTROLS):
        record = tracked.get(str(index), {})
        controls.append(
            {
                "index": index,
                "control": text,
                "status": record.get("status", "not_started"),
                "note": record.get("note", ""),
                "updated_at": record.get("updated_at"),
            }
        )
    return {"active_cluster": active_host(), "controls": controls}


@app.post("/api/manual-controls")
def update_manual_control(
    payload: ManualUpdate,
    _: tuple[str, dict[str, Any]] = Depends(require_csrf),
) -> dict[str, Any]:
    if payload.index >= len(MANUAL_CONTROLS):
        raise HTTPException(404, "Manual control not found.")
    if not active_host():
        raise HTTPException(409, "Activate a cluster workspace first.")
    state = active_state()
    tracked = state.setdefault("manual_controls", {})
    tracked[str(payload.index)] = {
        "status": payload.status,
        "note": payload.note.strip(),
        "updated_at": utc_now(),
    }
    write_state(state)
    return {"saved": True}


@app.post("/api/context/close")
def close_context(
    payload: ContextClose,
    _: tuple[str, dict[str, Any]] = Depends(require_csrf),
) -> dict[str, Any]:
    global current_job_id
    host = active_host()
    if not host:
        return {"closed": True}
    if current_job_id and jobs.get(current_job_id, {}).get("status") == "running":
        raise HTTPException(409, "Wait for the active operation to finish.")
    expected = f"CLOSE {host}"
    if not secrets.compare_digest(payload.confirmation, expected):
        raise HTTPException(422, f"Type exactly: {expected}")
    write_state(
        {
            "active_cluster": None,
            "latest_dry_run": None,
            "latest_rollback_preview": None,
            "manual_controls": {},
        }
    )
    current_job_id = None
    return {
        "closed": True,
        "archived_cluster": host,
        "note": "Evidence and audit files were preserved locally.",
    }


@app.get("/api/capabilities")
def capabilities(request: Request) -> dict[str, Any]:
    get_session(request)
    return {
        "automates": [
            "Strict SSH host-key trust and authenticated CVM/PCVM connections",
            "Preflight health, DNS, NTP, version, and cluster-state checks",
            "Runtime discovery of security parameters supported by the installed release",
            "CVM, AHV, and PCVM security-parameter planning and verified readback",
            "Optional remote syslog configuration through the verified engine",
            "Rollback manifests for values changed by the tool",
            "Text, JSON, CSV, console, baseline, post-change, and evidence reports",
            "Optional read-only cluster identity using Nutanix Cluster Management v4.2",
        ],
        "does_not_automate": [
            {
                "item": "Cluster lockdown",
                "why": "A mistake can strand administrators; the tool reports readiness only.",
            },
            {
                "item": "Credential rotation and break-glass validation",
                "why": "Requires the client vault, account ownership, and recovery procedures.",
            },
            {
                "item": "LDAPS, RBAC, CAC/PIV, and certificate replacement",
                "why": "Identity and trust changes require organization-specific dependencies and staged testing.",
            },
            {
                "item": "Encryption/KMS enablement",
                "why": "Can affect data availability and requires escrow and ISSO approval.",
            },
            {
                "item": "Network segmentation and upstream ACLs",
                "why": "These controls live outside the cluster and require network-owner coordination.",
            },
            {
                "item": "External SCAP/SCC or STIG Viewer attestation",
                "why": "The tool produces evidence but is not an accredited external scanner.",
            },
            {
                "item": "Universal v4 security writes",
                "why": (
                    "Nutanix v4.2 is used for read-only identity when available. The control-specific "
                    "v4 mutation surface is not assumed; security writes use the verified nCLI path."
                ),
            },
        ],
    }


@app.get("/api/docs/client-guide")
def client_guide(request: Request) -> FileResponse:
    get_session(request)
    return FileResponse(
        DOCS_DIR / "Nutanix_STIG_Hardening_Client_Execution_Guide.docx",
        filename="Nutanix_STIG_Hardening_Client_Execution_Guide.docx",
    )


@app.get("/api/docs/universal-guide")
def universal_guide(request: Request) -> FileResponse:
    get_session(request)
    return FileResponse(
        DOCS_DIR / "Nutanix_STIG_Control_Center_Universal_Client_Guide.md",
        filename="Nutanix_STIG_Control_Center_Universal_Client_Guide.md",
    )


@app.get("/api/docs/verification-report")
def verification_report(request: Request) -> FileResponse:
    get_session(request)
    return FileResponse(
        DOCS_DIR / "Nutanix_STIG_Script_Verification_Report.md",
        filename="Nutanix_STIG_Script_Verification_Report.md",
    )


def main() -> None:
    global INSTANCE_ID
    parser = argparse.ArgumentParser(description="Nutanix STIG Control Center")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8766)
    parser.add_argument("--instance-id", default="unmanaged")
    args = parser.parse_args()
    if args.host not in {"127.0.0.1", "localhost", "::1"}:
        raise SystemExit("Refusing to bind beyond localhost")
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", args.instance_id):
        raise SystemExit("Invalid instance identifier")
    INSTANCE_ID = args.instance_id
    import uvicorn

    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
