#!/usr/bin/env python3
"""Cross-platform installer and service controller for Nutanix STIG Control Center."""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import signal
import socket
import subprocess
import sys
import time
import uuid
import venv
import webbrowser
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen


VERSION = "1.1.0"
ROOT = Path(__file__).resolve().parent
APP_DIR = ROOT / "app"
RUNTIME_DIR = ROOT / ".runtime"
VENV_DIR = RUNTIME_DIR / "venv"
STATE_FILE = RUNTIME_DIR / "service.json"
LOCK_FILE = RUNTIME_DIR / "controller.lock"
DATA_DIR = APP_DIR / "data"
LOG_FILE = DATA_DIR / "control-center-service.log"
REQUIREMENTS = APP_DIR / "requirements.txt"
SERVER = APP_DIR / "server.py"
MIN_PYTHON = (3, 10)


class ControlCenterError(RuntimeError):
    """Friendly controller error."""


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def ensure_supported_python() -> None:
    if sys.version_info < MIN_PYTHON:
        raise ControlCenterError(
            "Python 3.10 or newer is required. "
            f"This launcher is using Python {platform.python_version()}."
        )
    if sys.maxsize <= 2**32:
        raise ControlCenterError("A 64-bit Python installation is required.")


def ensure_layout() -> None:
    if not SERVER.is_file() or not REQUIREMENTS.is_file():
        raise ControlCenterError(
            "The application files are incomplete. Extract the entire package "
            "before starting it."
        )
    try:
        RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        probe = RUNTIME_DIR / ".write-test"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
    except OSError as exc:
        raise ControlCenterError(
            f"The extracted application folder is not writable: {ROOT}. "
            "Move it to a user-controlled local folder."
        ) from exc


def runtime_python() -> Path:
    if os.name == "nt":
        return VENV_DIR / "Scripts" / "python.exe"
    return VENV_DIR / "bin" / "python"


def save_json(path: Path, value: dict) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2), encoding="utf-8")
    os.replace(temporary, path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def load_state() -> dict:
    try:
        value = json.loads(STATE_FILE.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def clear_state() -> None:
    try:
        STATE_FILE.unlink()
    except FileNotFoundError:
        pass


@contextmanager
def controller_lock():
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    descriptor = None
    try:
        descriptor = os.open(
            str(LOCK_FILE),
            os.O_CREAT | os.O_EXCL | os.O_WRONLY,
            0o600,
        )
        os.write(descriptor, f"{os.getpid()} {now()}\n".encode())
    except FileExistsError as exc:
        try:
            age = time.time() - LOCK_FILE.stat().st_mtime
        except OSError:
            age = 0
        if age > 600:
            try:
                LOCK_FILE.unlink()
            except OSError:
                pass
            raise ControlCenterError(
                "A stale controller lock was cleared. Run the action again."
            ) from exc
        raise ControlCenterError(
            "Another install, start, stop, or repair action is already running."
        ) from exc
    try:
        yield
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            LOCK_FILE.unlink()
        except FileNotFoundError:
            pass


def run_checked(command: list[str], label: str) -> None:
    try:
        result = subprocess.run(command, cwd=ROOT, check=False)
    except OSError as exc:
        raise ControlCenterError(f"{label} could not start: {exc}") from exc
    if result.returncode:
        raise ControlCenterError(f"{label} failed with exit code {result.returncode}.")


def dependencies_work() -> bool:
    python = runtime_python()
    if not python.is_file():
        return False
    check = subprocess.run(
        [
            str(python),
            "-c",
            "import fastapi,httpx,paramiko,pydantic,uvicorn",
        ],
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return check.returncode == 0


def install_dependencies(repair: bool = False) -> None:
    ensure_supported_python()
    ensure_layout()
    if repair:
        expected_parent = RUNTIME_DIR.resolve()
        if VENV_DIR.exists() and VENV_DIR.resolve().parent != expected_parent:
            raise ControlCenterError("Refusing to repair an unexpected runtime path.")
        print("Rebuilding the isolated application environment…")
        builder = venv.EnvBuilder(with_pip=True, clear=True)
        try:
            builder.create(VENV_DIR)
        except Exception as exc:
            raise ControlCenterError(
                "The private Python environment could not be rebuilt. "
                "On Debian/Ubuntu, confirm the python3-venv package is installed."
            ) from exc
    elif not runtime_python().is_file():
        print("Creating the isolated application environment…")
        builder = venv.EnvBuilder(with_pip=True)
        try:
            builder.create(VENV_DIR)
        except Exception as exc:
            raise ControlCenterError(
                "The private Python environment could not be created. "
                "On Debian/Ubuntu, confirm the python3-venv package is installed."
            ) from exc

    python = runtime_python()
    if not python.is_file():
        raise ControlCenterError("The isolated Python environment could not be created.")

    command = [
        str(python),
        "-m",
        "pip",
        "install",
        "--disable-pip-version-check",
        "--no-input",
        "-r",
        str(REQUIREMENTS),
    ]
    wheelhouse = ROOT / "wheelhouse"
    if wheelhouse.is_dir() and any(wheelhouse.iterdir()):
        command.extend(["--no-index", "--find-links", str(wheelhouse)])
        print("Installing from the local wheelhouse…")
    else:
        print("Installing the pinned application dependencies…")
    run_checked(command, "Dependency installation")
    if not dependencies_work():
        raise ControlCenterError("The isolated environment did not pass its import check.")
    print("Installation complete. Cluster evidence and settings were not changed.")


def health(state: dict, timeout: float = 1.0) -> dict | None:
    url = state.get("url")
    instance_id = state.get("instance_id")
    if not isinstance(url, str) or not isinstance(instance_id, str):
        return None
    try:
        request = Request(f"{url}/api/health", headers={"Accept": "application/json"})
        with urlopen(request, timeout=timeout) as response:
            body = json.load(response)
        if (
            isinstance(body, dict)
            and body.get("status") == "ok"
            and body.get("instance_id") == instance_id
            and body.get("local_only") is True
        ):
            return body
    except (OSError, URLError, ValueError, TimeoutError):
        pass
    return None


def running_state() -> tuple[dict, dict] | tuple[None, None]:
    state = load_state()
    result = health(state)
    if result:
        return state, result
    return None, None


def choose_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def log_tail(lines: int = 30) -> str:
    try:
        content = LOG_FILE.read_text(encoding="utf-8", errors="replace").splitlines()
        return "\n".join(content[-lines:])
    except OSError:
        return ""


def terminate_pid(pid: int, force: bool = False) -> None:
    if pid < 1:
        return
    if os.name == "nt":
        command = ["taskkill", "/PID", str(pid), "/T"]
        if force:
            command.append("/F")
        subprocess.run(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    else:
        try:
            os.killpg(pid, signal.SIGKILL if force else signal.SIGTERM)
        except ProcessLookupError:
            pass


def start_service(open_browser: bool = True) -> dict:
    ensure_supported_python()
    ensure_layout()
    existing, _ = running_state()
    if existing:
        print(f"Control Center is already running at {existing['url']}")
        if open_browser:
            webbrowser.open(existing["url"], new=2)
        return existing

    if not dependencies_work():
        install_dependencies()

    port = choose_port()
    instance_id = uuid.uuid4().hex
    url = f"http://127.0.0.1:{port}"
    command = [
        str(runtime_python()),
        str(SERVER),
        "--host",
        "127.0.0.1",
        "--port",
        str(port),
        "--instance-id",
        instance_id,
    ]
    environment = os.environ.copy()
    environment["PYTHONUNBUFFERED"] = "1"
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with LOG_FILE.open("a", encoding="utf-8") as log:
        log.write(f"\n[{now()}] Starting Control Center {VERSION} at {url}\n")
        log.flush()
        options = {
            "cwd": str(APP_DIR),
            "env": environment,
            "stdin": subprocess.DEVNULL,
            "stdout": log,
            "stderr": subprocess.STDOUT,
            "close_fds": True,
        }
        if os.name == "nt":
            options["creationflags"] = (
                subprocess.CREATE_NEW_PROCESS_GROUP
                | subprocess.DETACHED_PROCESS
                | subprocess.CREATE_NO_WINDOW
            )
        else:
            options["start_new_session"] = True
        process = subprocess.Popen(command, **options)

    state = {
        "version": VERSION,
        "pid": process.pid,
        "instance_id": instance_id,
        "url": url,
        "started_at": now(),
        "root": str(ROOT),
    }
    save_json(STATE_FILE, state)
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        if health(state, timeout=0.5):
            print(f"Control Center is running at {url}")
            if open_browser:
                webbrowser.open(url, new=2)
            return state
        if process.poll() is not None:
            break
        time.sleep(0.25)

    terminate_pid(process.pid)
    time.sleep(0.5)
    terminate_pid(process.pid, force=True)
    clear_state()
    details = log_tail()
    raise ControlCenterError(
        "The local service did not become ready."
        + (f"\n\nRecent service log:\n{details}" if details else "")
    )


def stop_service(force_stop: bool = False) -> None:
    state, result = running_state()
    if not state:
        clear_state()
        print("Control Center is not running.")
        return
    if result.get("operation_running") and not force_stop:
        raise ControlCenterError(
            "A cluster operation is running. Wait for it to finish before stopping. "
            "For an authorized emergency interruption only, run "
            "'control_center.py stop --force-stop'."
        )
    pid = state.get("pid")
    if not isinstance(pid, int):
        raise ControlCenterError("The service state does not contain a valid process ID.")
    print("Stopping the local Control Center…")
    terminate_pid(pid)
    deadline = time.monotonic() + (1 if os.name == "nt" else 10)
    while time.monotonic() < deadline:
        if not health(state, timeout=0.4):
            clear_state()
            print("Control Center stopped. Evidence and settings were preserved.")
            return
        time.sleep(0.25)
    terminate_pid(pid, force=True)
    time.sleep(0.5)
    if health(state, timeout=0.5):
        raise ControlCenterError(
            "The verified Control Center process did not stop. "
            f"Review {LOG_FILE} and stop process {pid} through the operating system."
        )
    clear_state()
    print("Control Center stopped. Evidence and settings were preserved.")


def show_status() -> None:
    state, result = running_state()
    print(f"Nutanix STIG Control Center {VERSION}")
    print(f"Platform      : {platform.system()} {platform.release()}")
    print(f"Python        : {platform.python_version()} ({sys.executable})")
    print(f"Application   : {ROOT}")
    print(f"Environment   : {'ready' if dependencies_work() else 'not installed'}")
    print(f"Service       : {'running' if state else 'stopped'}")
    if state:
        print(f"Local URL     : {state['url']}")
        print(f"Process ID    : {state['pid']}")
        print(f"Active cluster: {result.get('active_cluster') or 'none'}")
        print(
            "Operation     : "
            + ("running" if result.get("operation_running") else "idle")
        )
    print(f"Evidence/data : {DATA_DIR}")
    print(f"Service log   : {LOG_FILE}")


def open_service() -> None:
    state, _ = running_state()
    if not state:
        state = start_service(open_browser=False)
    webbrowser.open(state["url"], new=2)
    print(f"Opened {state['url']}")


def doctor() -> None:
    ensure_supported_python()
    ensure_layout()
    print("Nutanix STIG Control Center diagnostics")
    print("---------------------------------------")
    print(f"[PASS] Python {platform.python_version()} is supported")
    print(f"[PASS] Application folder is complete and writable")
    if dependencies_work():
        print("[PASS] Isolated dependencies import successfully")
    else:
        print("[WARN] Isolated dependencies are not installed")
    state, result = running_state()
    if state:
        print(f"[PASS] Local service identity verified at {state['url']}")
        print(
            "[PASS] Service reports localhost-only mode"
            if result.get("local_only")
            else "[FAIL] Service did not report localhost-only mode"
        )
    else:
        print("[INFO] Local service is stopped")
    print(f"[INFO] Evidence and settings: {DATA_DIR}")
    print("Diagnostics do not contact a Nutanix cluster.")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Install and operate the local Nutanix STIG Control Center."
    )
    parser.add_argument(
        "command",
        nargs="?",
        default="start",
        choices=("install", "start", "stop", "restart", "open", "status", "doctor", "repair"),
    )
    parser.add_argument(
        "--no-browser",
        action="store_true",
        help="Start without opening the default browser.",
    )
    parser.add_argument(
        "--force-stop",
        action="store_true",
        help="Emergency only: allow stop while a cluster operation is active.",
    )
    parser.add_argument("--version", action="version", version=VERSION)
    args = parser.parse_args()
    try:
        with controller_lock():
            if args.command == "install":
                install_dependencies()
            elif args.command == "start":
                start_service(open_browser=not args.no_browser)
            elif args.command == "stop":
                stop_service(force_stop=args.force_stop)
            elif args.command == "restart":
                stop_service(force_stop=args.force_stop)
                start_service(open_browser=not args.no_browser)
            elif args.command == "open":
                open_service()
            elif args.command == "status":
                show_status()
            elif args.command == "doctor":
                doctor()
            elif args.command == "repair":
                stop_service(force_stop=args.force_stop)
                install_dependencies(repair=True)
        return 0
    except ControlCenterError as exc:
        print(f"\nControl Center error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nCancelled.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
