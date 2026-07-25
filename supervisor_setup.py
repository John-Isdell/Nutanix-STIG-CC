#!/usr/bin/env python3
"""Cross-platform registration and lifecycle helpers for the local supervisor."""

from __future__ import annotations

import json
import os
import platform
import plistlib
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable
from urllib.error import URLError
from urllib.request import Request, urlopen

SUPERVISOR_HOST = "127.0.0.1"
SUPERVISOR_PORT = 8765
SUPERVISOR_URL = f"http://{SUPERVISOR_HOST}:{SUPERVISOR_PORT}"
WINDOWS_SHORTCUT_NAME = "Nutanix STIG Control Center Supervisor.lnk"
MACOS_LABEL = "com.nutanix.stig-control-center.supervisor"
LINUX_UNIT_NAME = "nutanix-stig-control-center-supervisor.service"

Progress = Callable[[str], None] | None


class SupervisorSetupError(RuntimeError):
    """Raised when OS registration or supervisor lifecycle work fails."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _emit(message: str, progress: Progress = None) -> None:
    if progress:
        progress(message)
    else:
        print(message)


def runtime_dir(root: Path) -> Path:
    return root / ".runtime"


def state_file(root: Path) -> Path:
    return runtime_dir(root) / "supervisor.json"


def registration_file(root: Path) -> Path:
    return runtime_dir(root) / "supervisor-registration.json"


def log_file(root: Path) -> Path:
    return runtime_dir(root) / "supervisor.log"


def windows_startup_shortcut_path(home: Path | None = None) -> Path:
    if home is None:
        appdata = os.environ.get("APPDATA")
        if appdata:
            startup_root = Path(appdata)
        else:
            startup_root = Path.home() / "AppData" / "Roaming"
    else:
        startup_root = home / "AppData" / "Roaming"
    return (
        startup_root
        / "Microsoft"
        / "Windows"
        / "Start Menu"
        / "Programs"
        / "Startup"
        / WINDOWS_SHORTCUT_NAME
    )


def supervisor_script(root: Path) -> Path:
    return root / "supervisor.py"


def macos_plist_path(home: Path) -> Path:
    return home / "Library" / "LaunchAgents" / f"{MACOS_LABEL}.plist"


def linux_unit_path(home: Path) -> Path:
    return home / ".config" / "systemd" / "user" / LINUX_UNIT_NAME


def _read_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def _write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2), encoding="utf-8")
    os.replace(temporary, path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _unlink(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        pass


def registration_status(root: Path) -> dict:
    return _read_json(registration_file(root))


def supervisor_health(root: Path, timeout: float = 1.0) -> dict | None:
    state = _read_json(state_file(root))
    instance_id = state.get("instance_id")
    if state.get("url") != SUPERVISOR_URL or not isinstance(instance_id, str):
        return None
    try:
        request = Request(
            f"{SUPERVISOR_URL}/api/health",
            headers={"Accept": "application/json"},
        )
        with urlopen(request, timeout=timeout) as response:
            body = json.load(response)
        if (
            isinstance(body, dict)
            and body.get("status") == "ok"
            and body.get("supervisor") is True
            and body.get("local_only") is True
            and body.get("instance_id") == instance_id
        ):
            return body
    except (OSError, URLError, ValueError, TimeoutError):
        pass
    return None


def wait_for_supervisor(root: Path, timeout: float = 20.0) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        health = supervisor_health(root, timeout=0.5)
        if health:
            return health
        time.sleep(0.25)
    details = ""
    try:
        lines = log_file(root).read_text(
            encoding="utf-8", errors="replace"
        ).splitlines()
        details = "\n".join(lines[-30:])
    except OSError:
        pass
    raise SupervisorSetupError(
        "The localhost supervisor did not become ready at "
        f"{SUPERVISOR_URL}."
        + (f"\n\nRecent supervisor log:\n{details}" if details else "")
    )


def host_python(python_executable: str | Path | None = None) -> Path:
    candidate = Path(
        python_executable
        or getattr(sys, "_base_executable", "")
        or sys.executable
    ).resolve()
    if os.name == "nt":
        pythonw = candidate.with_name("pythonw.exe")
        if pythonw.is_file():
            return pythonw
    return candidate


def _powershell_literal(value: str | Path) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def windows_startup_shortcut_command(
    root: Path,
    python_executable: str | Path,
    shortcut_path: Path,
) -> list[str]:
    arguments = subprocess.list2cmdline([str(supervisor_script(root))])
    script = (
        f"$shortcutPath={_powershell_literal(shortcut_path)};"
        f"$targetPath={_powershell_literal(host_python(python_executable))};"
        f"$arguments={_powershell_literal(arguments)};"
        f"$workingDirectory={_powershell_literal(root)};"
        "$shell=New-Object -ComObject WScript.Shell;"
        "$shortcut=$shell.CreateShortcut($shortcutPath);"
        "$shortcut.TargetPath=$targetPath;"
        "$shortcut.Arguments=$arguments;"
        "$shortcut.WorkingDirectory=$workingDirectory;"
        "$shortcut.WindowStyle=7;"
        "$shortcut.Description='Nutanix STIG Control Center localhost supervisor';"
        "$shortcut.Save()"
    )
    return [
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        script,
    ]


def _start_windows_supervisor(
    root: Path,
    python_executable: str | Path,
) -> None:
    creation_flags = 0
    if os.name == "nt":
        creation_flags = (
            getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            | getattr(subprocess, "DETACHED_PROCESS", 0)
        )
    try:
        subprocess.Popen(
            [
                str(host_python(python_executable)),
                str(supervisor_script(root)),
            ],
            cwd=root,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            creationflags=creation_flags,
        )
    except OSError as exc:
        raise SupervisorSetupError(
            f"Windows supervisor start could not begin: {exc}"
        ) from exc


def macos_launch_agent(
    root: Path,
    python_executable: str | Path,
) -> dict:
    return {
        "Label": MACOS_LABEL,
        "ProgramArguments": [
            str(host_python(python_executable)),
            str(supervisor_script(root)),
        ],
        "WorkingDirectory": str(root),
        "RunAtLoad": True,
        "KeepAlive": {"SuccessfulExit": False},
        "ProcessType": "Interactive",
        "StandardOutPath": str(log_file(root)),
        "StandardErrorPath": str(log_file(root)),
    }


def _systemd_quote(value: str | Path) -> str:
    text = str(value).replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%")
    return f'"{text}"'


def linux_systemd_unit(
    root: Path,
    python_executable: str | Path,
) -> str:
    command = " ".join(
        (
            _systemd_quote(host_python(python_executable)),
            _systemd_quote(supervisor_script(root)),
        )
    )
    return "\n".join(
        [
            "[Unit]",
            "Description=Nutanix STIG Control Center localhost supervisor",
            "After=default.target",
            "",
            "[Service]",
            "Type=simple",
            f"ExecStart={command}",
            f"WorkingDirectory={_systemd_quote(root)}",
            "Restart=on-failure",
            "RestartSec=3",
            "NoNewPrivileges=true",
            "PrivateTmp=true",
            "",
            "[Install]",
            "WantedBy=default.target",
            "",
        ]
    )


def _run(
    command: list[str],
    label: str,
    progress: Progress = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            command,
            cwd=None,
            capture_output=True,
            text=True,
            errors="replace",
            check=False,
        )
    except OSError as exc:
        if check:
            raise SupervisorSetupError(f"{label} could not start: {exc}") from exc
        return subprocess.CompletedProcess(command, 127, "", str(exc))
    for stream in (result.stdout, result.stderr):
        for line in stream.splitlines():
            if line.strip():
                _emit(line.rstrip(), progress)
    if check and result.returncode:
        raise SupervisorSetupError(
            f"{label} failed with exit code {result.returncode}."
        )
    return result


def _rollback_registration(
    root: Path,
    selected_platform: str,
    selected_home: Path,
    progress: Progress,
) -> bool:
    """Best-effort rollback for an installation that did not become healthy."""
    _emit("Supervisor registration failed; rolling back automatic startup…", progress)
    if selected_platform == "Windows":
        marker = registration_status(root)
        target = Path(
            marker.get("path")
            or windows_startup_shortcut_path(selected_home)
        )
        try:
            _unlink(target)
            _unlink(registration_file(root))
            return True
        except OSError:
            return False
    if selected_platform == "Darwin":
        service = f"gui/{os.getuid()}/{MACOS_LABEL}"
        _run(["launchctl", "bootout", service], "launchd rollback", progress, False)
        _unlink(macos_plist_path(selected_home))
        _unlink(registration_file(root))
        return True
    if selected_platform == "Linux":
        _run(
            ["systemctl", "--user", "disable", "--now", LINUX_UNIT_NAME],
            "systemd user rollback",
            progress,
            False,
        )
        _unlink(linux_unit_path(selected_home))
        _run(
            ["systemctl", "--user", "daemon-reload"],
            "systemd user rollback reload",
            progress,
            False,
        )
        _unlink(registration_file(root))
        return True
    return False


def register_supervisor(
    root: Path,
    python_executable: str | Path,
    progress: Progress = None,
    platform_name: str | None = None,
    home: Path | None = None,
) -> dict:
    root = root.resolve()
    if not supervisor_script(root).is_file():
        raise SupervisorSetupError(
            f"The supervisor program is missing: {supervisor_script(root)}"
        )
    runtime_dir(root).mkdir(parents=True, exist_ok=True)
    selected_platform = platform_name or platform.system()
    selected_home = (home or Path.home()).resolve()
    python = host_python(python_executable)
    _emit(f"Registering the localhost supervisor for {selected_platform}…", progress)
    registration_started = False
    try:
        if selected_platform == "Windows":
            target = windows_startup_shortcut_path(
                home if home is not None else None
            )
            target.parent.mkdir(parents=True, exist_ok=True)
            _run(
                windows_startup_shortcut_command(root, python, target),
                "Windows Startup-folder shortcut registration",
                progress,
            )
            registration_started = True
            marker = {
                "platform": selected_platform,
                "kind": "Startup-folder shortcut",
                "identifier": WINDOWS_SHORTCUT_NAME,
                "path": str(target),
                "registered_at": utc_now(),
            }
            _write_json(registration_file(root), marker)
            _start_windows_supervisor(root, python)
        elif selected_platform == "Darwin":
            target = macos_plist_path(selected_home)
            target.parent.mkdir(parents=True, exist_ok=True)
            domain = f"gui/{os.getuid()}"
            service = f"{domain}/{MACOS_LABEL}"
            _run(
                ["launchctl", "bootout", service],
                "Existing launchd unload",
                progress,
                False,
            )
            target.write_bytes(
                plistlib.dumps(
                    macos_launch_agent(root, python),
                    fmt=plistlib.FMT_XML,
                    sort_keys=False,
                )
            )
            registration_started = True
            marker = {
                "platform": selected_platform,
                "kind": "launchd user agent",
                "identifier": MACOS_LABEL,
                "path": str(target),
                "registered_at": utc_now(),
            }
            _write_json(registration_file(root), marker)
            _run(
                ["launchctl", "bootstrap", domain, str(target)],
                "launchd registration",
                progress,
            )
            _run(["launchctl", "enable", service], "launchd enable", progress)
            _run(
                ["launchctl", "kickstart", "-k", service],
                "launchd start",
                progress,
            )
        elif selected_platform == "Linux":
            target = linux_unit_path(selected_home)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(linux_systemd_unit(root, python), encoding="utf-8")
            registration_started = True
            marker = {
                "platform": selected_platform,
                "kind": "systemd user service",
                "identifier": LINUX_UNIT_NAME,
                "path": str(target),
                "registered_at": utc_now(),
            }
            _write_json(registration_file(root), marker)
            _run(
                ["systemctl", "--user", "daemon-reload"],
                "systemd user reload",
                progress,
            )
            _run(
                ["systemctl", "--user", "enable", "--now", LINUX_UNIT_NAME],
                "systemd user service registration",
                progress,
            )
        else:
            raise SupervisorSetupError(
                "Automatic supervisor registration is not supported on "
                f"{selected_platform}."
            )
        wait_for_supervisor(root)
    except (OSError, SupervisorSetupError) as exc:
        rollback_ok = not registration_started or _rollback_registration(
            root,
            selected_platform,
            selected_home,
            progress,
        )
        if not rollback_ok:
            raise SupervisorSetupError(
                f"{exc} Automatic-start rollback also failed; remove the "
                f"Windows Startup-folder shortcut manually and review "
                f"{log_file(root)}."
            ) from exc
        if isinstance(exc, SupervisorSetupError):
            raise
        raise SupervisorSetupError(
            f"Supervisor registration could not be written: {exc}"
        ) from exc
    _emit(f"Supervisor is ready at {SUPERVISOR_URL}", progress)
    return marker


def unregister_supervisor(
    root: Path,
    progress: Progress = None,
    platform_name: str | None = None,
    home: Path | None = None,
    stop_running: bool = True,
) -> None:
    root = root.resolve()
    marker = registration_status(root)
    selected_platform = platform_name or marker.get("platform") or platform.system()
    selected_home = (home or Path.home()).resolve()
    _emit(f"Removing the {selected_platform} supervisor registration…", progress)

    if selected_platform == "Windows":
        target = Path(
            marker.get("path")
            or windows_startup_shortcut_path(
                home if home is not None else None
            )
        )
        try:
            _unlink(target)
        except OSError as exc:
            raise SupervisorSetupError(
                f"Windows Startup-folder shortcut removal failed: {exc}"
            ) from exc
        _unlink(registration_file(root))
    elif selected_platform == "Darwin":
        target = macos_plist_path(selected_home)
        service = f"gui/{os.getuid()}/{MACOS_LABEL}"
        registered = bool(marker) or target.exists()
        command = (
            ["launchctl", "bootout", service]
            if stop_running
            else ["launchctl", "disable", service]
        )
        _run(command, "launchd removal", progress, registered)
        _unlink(target)
        _unlink(registration_file(root))
    elif selected_platform == "Linux":
        target = linux_unit_path(selected_home)
        registered = bool(marker) or target.exists()
        _run(
            ["systemctl", "--user", "disable", LINUX_UNIT_NAME],
            "systemd user disable",
            progress,
            registered,
        )
        _unlink(target)
        _unlink(registration_file(root))
        _run(
            ["systemctl", "--user", "daemon-reload"],
            "systemd user reload",
            progress,
            registered,
        )
        if stop_running:
            _run(
                ["systemctl", "--user", "stop", LINUX_UNIT_NAME],
                "systemd user service stop",
                progress,
                False,
            )
    else:
        raise SupervisorSetupError(
            f"Automatic supervisor removal is not supported on {selected_platform}."
        )
    _emit("Supervisor registration removed.", progress)


def stop_supervisor_process(
    root: Path,
    progress: Progress = None,
    timeout: float = 10.0,
) -> None:
    root = root.resolve()
    state = _read_json(state_file(root))
    health = supervisor_health(root)
    if not health:
        _unlink(state_file(root))
        return
    pid = state.get("pid")
    if not isinstance(pid, int) or pid < 1:
        raise SupervisorSetupError("The supervisor state has no valid process ID.")
    _emit("Stopping the verified localhost supervisor…", progress)
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/PID", str(pid), "/T"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    else:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not supervisor_health(root, timeout=0.3):
            _unlink(state_file(root))
            return
        time.sleep(0.2)
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/PID", str(pid), "/T", "/F"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    else:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    time.sleep(0.3)
    if supervisor_health(root, timeout=0.3):
        raise SupervisorSetupError(
            f"The verified supervisor process {pid} did not stop."
        )
    _unlink(state_file(root))
