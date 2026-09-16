from __future__ import annotations

import datetime as dt
import json
import re
import threading
import uuid
from pathlib import Path


def utcnow() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


class ScanProfileManager:
    """Small registry that keeps each saved scan in its own SQLite database."""

    def __init__(self, config_dir: Path):
        self.config_dir = config_dir
        self.registry_path = config_dir / "scan_profiles.json"
        self.scans_dir = config_dir / "scans"
        self.lock = threading.Lock()
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.scans_dir.mkdir(parents=True, exist_ok=True)
        with self.lock:
            if not self.registry_path.exists():
                self._create_initial_registry()

    def _create_initial_registry(self) -> None:
        profile_id = "original"
        legacy_db = self.config_dir / "catalog.sqlite3"
        if legacy_db.exists():
            relative_db = "catalog.sqlite3"
            name = "Original Scan"
        else:
            relative_db = f"scans/{profile_id}/catalog.sqlite3"
            name = "Scan 1"
        data = {
            "version": 1,
            "active": profile_id,
            "profiles": [{
                "id": profile_id, "name": name, "db": relative_db,
                "created_at": utcnow(), "last_used_at": utcnow(),
            }],
        }
        self._write_unlocked(data)

    def _read_unlocked(self) -> dict:
        try:
            data = json.loads(self.registry_path.read_text(encoding="utf-8"))
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"Unable to read saved-scan registry: {exc}") from exc
        if not data.get("profiles") or not data.get("active"):
            raise RuntimeError("Saved-scan registry is empty or invalid.")
        return data

    def _write_unlocked(self, data: dict) -> None:
        temporary = self.registry_path.with_suffix(".tmp")
        temporary.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        temporary.replace(self.registry_path)

    @staticmethod
    def _clean_name(name: str) -> str:
        cleaned = re.sub(r"\s+", " ", name).strip()
        if not cleaned:
            raise ValueError("Enter a name for the saved scan.")
        return cleaned[:80]

    def _public_profile(self, profile: dict, active_id: str) -> dict:
        item = dict(profile)
        item["active"] = item["id"] == active_id
        item["db_path"] = str((self.config_dir / item["db"]).resolve())
        return item

    def list_profiles(self) -> list[dict]:
        with self.lock:
            data = self._read_unlocked()
            return [self._public_profile(item, data["active"]) for item in data["profiles"]]

    def get_profile(self, profile_id: str) -> dict:
        with self.lock:
            data = self._read_unlocked()
            for item in data["profiles"]:
                if item["id"] == profile_id:
                    return self._public_profile(item, data["active"])
        raise KeyError("Saved scan not found.")

    def active_profile(self) -> dict:
        with self.lock:
            data = self._read_unlocked()
            for item in data["profiles"]:
                if item["id"] == data["active"]:
                    return self._public_profile(item, data["active"])
        raise RuntimeError("The active saved scan is missing from the registry.")

    def create(self, name: str) -> dict:
        name = self._clean_name(name)
        with self.lock:
            data = self._read_unlocked()
            profile_id = uuid.uuid4().hex[:12]
            relative_db = f"scans/{profile_id}/catalog.sqlite3"
            profile = {
                "id": profile_id, "name": name, "db": relative_db,
                "created_at": utcnow(), "last_used_at": utcnow(),
            }
            data["profiles"].append(profile)
            data["active"] = profile_id
            self._write_unlocked(data)
            return self._public_profile(profile, profile_id)

    def activate(self, profile_id: str) -> dict:
        with self.lock:
            data = self._read_unlocked()
            selected = None
            for item in data["profiles"]:
                if item["id"] == profile_id:
                    item["last_used_at"] = utcnow()
                    selected = item
                    break
            if selected is None:
                raise KeyError("Saved scan not found.")
            data["active"] = profile_id
            self._write_unlocked(data)
            return self._public_profile(selected, profile_id)

