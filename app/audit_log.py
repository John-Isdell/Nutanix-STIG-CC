"""Append-only, tamper-evident audit ledger for the local Control Center."""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

GENESIS_HASH = "0" * 64
DEFAULT_SETTINGS = {"retention_days": 3650, "rotation": "monthly"}
SENSITIVE_TERMS = (
    "password",
    "passphrase",
    "private_key",
    "api_key",
    "secret",
    "credential",
    "authorization",
    "cookie",
    "csrf",
    "token",
    "typed_confirmation",
)


class AuditIntegrityError(RuntimeError):
    """Raised when the existing ledger does not match its integrity state."""


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2), encoding="utf-8")
    os.replace(temporary, path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _read_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return default


def redact(value: Any, key: str = "") -> Any:
    """Recursively redact values whose field names indicate credentials."""
    lowered = key.lower()
    if key and any(term in lowered for term in SENSITIVE_TERMS):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(item_key): redact(item_value, str(item_key)) for item_key, item_value in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, tuple):
        return [redact(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _parse_timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


class AuditLedger:
    """Manage an append-only set of rotated, globally hash-chained JSONL files."""

    def __init__(self, root: Path, legacy_file: Path | None = None):
        self.root = root
        self.settings_file = root / "settings.json"
        self.anchor_file = root / "chain-anchor.json"
        self.state_file = root / "chain-state.json"
        self.legacy_file = legacy_file
        self.root.mkdir(parents=True, exist_ok=True)

    def settings(self) -> dict[str, Any]:
        saved = _read_json(self.settings_file, {})
        rotation = saved.get("rotation", DEFAULT_SETTINGS["rotation"])
        retention_days = saved.get("retention_days", DEFAULT_SETTINGS["retention_days"])
        if rotation not in {"daily", "monthly"}:
            rotation = DEFAULT_SETTINGS["rotation"]
        try:
            retention_days = int(retention_days)
        except (TypeError, ValueError):
            retention_days = DEFAULT_SETTINGS["retention_days"]
        return {
            "rotation": rotation,
            "retention_days": max(365, min(retention_days, 7300)),
        }

    def update_settings(self, retention_days: int, rotation: str) -> dict[str, Any]:
        if rotation not in {"daily", "monthly"}:
            raise ValueError("rotation must be daily or monthly")
        if not 365 <= retention_days <= 7300:
            raise ValueError("retention_days must be between 365 and 7300")
        settings = {"retention_days": retention_days, "rotation": rotation}
        _write_json(self.settings_file, settings)
        return settings

    def _files(self) -> list[Path]:
        return sorted(self.root.glob("audit-*.jsonl"))

    def _file_metadata(self) -> dict[str, dict[str, int]]:
        metadata = {}
        for path in self._files():
            stat = path.stat()
            metadata[path.name] = {"size": stat.st_size, "mtime_ns": stat.st_mtime_ns}
        return metadata

    def _bucket_path(
        self,
        timestamp: datetime,
        state: dict[str, Any],
    ) -> tuple[Path, str, str]:
        rotation = self.settings()["rotation"]
        bucket_id = timestamp.strftime("%Y-%m-%d") if rotation == "daily" else timestamp.strftime("%Y-%m")
        saved_name = str(state.get("bucket_file") or "")
        if (
            state.get("bucket_id") == bucket_id
            and state.get("rotation") == rotation
            and saved_name
            and (self.root / saved_name).is_file()
        ):
            return self.root / saved_name, bucket_id, rotation
        stem = timestamp.strftime("audit-%Y%m%dT%H%M%SZ")
        next_sequence = int(state.get("last_sequence") or 0) + 1
        path = self.root / f"audit-{next_sequence:020d}-{stem[6:]}-{rotation}.jsonl"
        return path, bucket_id, rotation

    def _anchor(self) -> dict[str, Any]:
        return _read_json(
            self.anchor_file,
            {"previous_hash": GENESIS_HASH, "last_pruned_sequence": 0},
        )

    def _state(self) -> dict[str, Any]:
        return _read_json(
            self.state_file,
            {"last_hash": self._anchor()["previous_hash"], "last_sequence": self._anchor()["last_pruned_sequence"]},
        )

    @staticmethod
    def _entry_hash(entry: dict[str, Any]) -> str:
        canonical = {key: value for key, value in entry.items() if key != "entry_hash"}
        encoded = json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
            "utf-8"
        )
        return hashlib.sha256(encoded).hexdigest()

    def _read_entries(self) -> list[dict[str, Any]]:
        entries: list[dict[str, Any]] = []
        for path in self._files():
            try:
                lines = path.read_text(encoding="utf-8").splitlines()
            except OSError as exc:
                raise AuditIntegrityError(f"Could not read {path.name}: {exc}") from exc
            for line_number, line in enumerate(lines, start=1):
                if not line.strip():
                    continue
                try:
                    item = json.loads(line)
                except ValueError as exc:
                    raise AuditIntegrityError(
                        f"Invalid JSON in {path.name} at line {line_number}"
                    ) from exc
                if not isinstance(item, dict):
                    raise AuditIntegrityError(
                        f"Invalid audit entry in {path.name} at line {line_number}"
                    )
                entries.append(item)
        return entries

    def verify(self) -> dict[str, Any]:
        anchor = self._anchor()
        expected_hash = str(anchor.get("previous_hash") or GENESIS_HASH)
        expected_sequence = int(anchor.get("last_pruned_sequence") or 0) + 1
        checked = 0
        problems: list[str] = []
        try:
            entries = self._read_entries()
        except AuditIntegrityError as exc:
            return {"ok": False, "entries_checked": 0, "problems": [str(exc)]}
        for item in entries:
            sequence = item.get("sequence")
            if sequence != expected_sequence:
                problems.append(
                    f"Sequence gap: expected {expected_sequence}, found {sequence}"
                )
                break
            if item.get("previous_hash") != expected_hash:
                problems.append(f"Hash-chain break at sequence {sequence}")
                break
            calculated = self._entry_hash(item)
            if item.get("entry_hash") != calculated:
                problems.append(f"Entry hash mismatch at sequence {sequence}")
                break
            expected_hash = calculated
            expected_sequence += 1
            checked += 1
        state = self._state()
        if not problems and (
            state.get("last_hash") != expected_hash
            or int(state.get("last_sequence") or 0) != expected_sequence - 1
        ):
            problems.append("Ledger tail does not match the protected chain state")
        return {
            "ok": not problems,
            "entries_checked": checked,
            "last_sequence": expected_sequence - 1,
            "last_hash": expected_hash,
            "problems": problems,
        }

    def _prune_expired_prefix(self, now: datetime) -> list[str]:
        files = self._files()
        if len(files) < 2:
            return []
        cutoff = now - timedelta(days=self.settings()["retention_days"])
        expired: list[Path] = []
        for path in files[:-1]:
            entries = []
            try:
                entries = [
                    json.loads(line)
                    for line in path.read_text(encoding="utf-8").splitlines()
                    if line.strip()
                ]
            except (OSError, ValueError):
                break
            if not entries:
                expired.append(path)
                continue
            try:
                last_time = _parse_timestamp(str(entries[-1]["timestamp"]))
            except (KeyError, TypeError, ValueError):
                break
            if last_time >= cutoff:
                break
            expired.append(path)
        if not expired:
            return []
        last_entry: dict[str, Any] | None = None
        for path in expired:
            for line in path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    last_entry = json.loads(line)
        if last_entry:
            _write_json(
                self.anchor_file,
                {
                    "previous_hash": last_entry["entry_hash"],
                    "last_pruned_sequence": last_entry["sequence"],
                    "pruned_at": now.isoformat(timespec="seconds"),
                    "pruned_files": [path.name for path in expired],
                },
            )
        for path in expired:
            path.unlink()
        return [path.name for path in expired]

    def append(
        self,
        *,
        actor_id: str,
        source: str,
        action: str,
        target_host: str | None,
        result: str,
        details: dict[str, Any] | None = None,
        timestamp: str | None = None,
    ) -> dict[str, Any]:
        now = _parse_timestamp(timestamp) if timestamp else datetime.now(timezone.utc)
        state = self._state()
        current_metadata = self._file_metadata()
        recorded_metadata = state.get("files", {})
        if current_metadata != recorded_metadata:
            integrity = self.verify()
            if not integrity["ok"]:
                raise AuditIntegrityError("; ".join(integrity["problems"]))
            state["last_hash"] = integrity["last_hash"]
            state["last_sequence"] = integrity["last_sequence"]
        pruned = self._prune_expired_prefix(now)
        safe_details = redact(details or {})
        if pruned:
            safe_details = {**safe_details, "retention_pruned_files": pruned}
        entry = {
            "version": 1,
            "sequence": int(state.get("last_sequence") or 0) + 1,
            "timestamp": now.isoformat(timespec="seconds"),
            "actor_id": str(actor_id)[:128],
            "source": str(source)[:64],
            "action": str(action)[:128],
            "target_host": str(target_host)[:253] if target_host else None,
            "result": str(result)[:64],
            "details": safe_details,
            "previous_hash": str(state.get("last_hash") or GENESIS_HASH),
        }
        entry["entry_hash"] = self._entry_hash(entry)
        path, bucket_id, rotation = self._bucket_path(now, state)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(json.dumps(entry, sort_keys=True, ensure_ascii=False) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        _write_json(
            self.state_file,
            {
                "last_hash": entry["entry_hash"],
                "last_sequence": entry["sequence"],
                "files": self._file_metadata(),
                "bucket_id": bucket_id,
                "bucket_file": path.name,
                "rotation": rotation,
            },
        )
        return entry

    def query(
        self,
        *,
        host: str | None = None,
        action: str | None = None,
        result: str | None = None,
        date_from: str | None = None,
        date_to: str | None = None,
        limit: int = 250,
    ) -> list[dict[str, Any]]:
        entries = self._read_entries()
        if host:
            entries = [entry for entry in entries if entry.get("target_host") == host]
        if action:
            needle = action.lower()
            entries = [entry for entry in entries if needle in str(entry.get("action", "")).lower()]
        if result:
            entries = [entry for entry in entries if entry.get("result") == result]
        if date_from:
            start = _parse_timestamp(date_from)
            entries = [entry for entry in entries if _parse_timestamp(entry["timestamp"]) >= start]
        if date_to:
            end = _parse_timestamp(date_to)
            entries = [entry for entry in entries if _parse_timestamp(entry["timestamp"]) <= end]
        return list(reversed(entries[-max(1, min(limit, 5000)) :]))

    def engagement_entries(self, host: str) -> list[dict[str, Any]]:
        return [entry for entry in self._read_entries() if entry.get("target_host") == host]

    def migrate_legacy(self) -> int:
        if not self.legacy_file or not self.legacy_file.is_file() or self._files():
            return 0
        legacy = _read_json(self.legacy_file, [])
        if not isinstance(legacy, list):
            return 0
        migrated = 0
        for item in sorted(legacy, key=lambda value: str(value.get("completed_at", ""))):
            if not isinstance(item, dict):
                continue
            self.append(
                actor_id="legacy-import",
                source="control-center",
                action="operation.completed",
                target_host=item.get("cluster_host"),
                result=item.get("status", "unknown"),
                timestamp=item.get("completed_at") or None,
                details={
                    "job_id": item.get("id"),
                    "mode": item.get("mode"),
                    "profile": item.get("profile"),
                    "scopes": item.get("scopes") or [],
                    "evidence_file": item.get("evidence_file"),
                    "rollback_manifests": item.get("rollback_manifests") or [],
                },
            )
            migrated += 1
        destination = self.legacy_file.with_name("audit.legacy-migrated.json")
        if migrated and not destination.exists():
            os.replace(self.legacy_file, destination)
        return migrated
