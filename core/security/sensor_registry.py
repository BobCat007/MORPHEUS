"""Persistent credential registry for MORPHEUS remote sensors."""

import hashlib
import hmac
import json
import os
import re
import secrets
import threading
from datetime import datetime, timezone
from pathlib import Path


_SENSOR_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


class SensorRegistryError(Exception):
    """Base exception for sensor registry operations."""


class SensorAlreadyExists(SensorRegistryError):
    pass


class SensorNotFound(SensorRegistryError):
    pass


class SensorRegistry:
    """Store sensor metadata and token hashes in a protected JSON file."""

    def __init__(self, path, initial_tokens=None):
        self.path = Path(path).expanduser().resolve()
        self.lock = threading.RLock()
        self.path.parent.mkdir(parents=True, exist_ok=True)

        if not self.path.exists():
            self._write({
                "version": 1,
                "sensors": {},
            })

            # Migrate existing environment-configured credentials.
            for sensor_id, token in (initial_tokens or {}).items():
                self._validate_sensor_id(sensor_id)
                self._sensors()[sensor_id] = {
                    "token_hash": self._hash_token(token),
                    "status": "active",
                    "last_seen": None,
                }

            self._save()

        self._load()

        # Backward-compatible migration for existing registry records.
        with self.lock:
            changed = False

            for record in self._sensors().values():
                if "last_seen" not in record:
                    record["last_seen"] = None
                    changed = True

            if changed:
                self._save()

    @staticmethod
    def _validate_sensor_id(sensor_id):
        if (
            not isinstance(sensor_id, str)
            or not _SENSOR_ID_PATTERN.fullmatch(sensor_id)
        ):
            raise ValueError("Invalid sensor ID.")

    @staticmethod
    def _hash_token(token):
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    @staticmethod
    def _timestamp():
        return datetime.now(timezone.utc).isoformat()

    def _load(self):
        with self.lock:
            try:
                data = json.loads(
                    self.path.read_text(encoding="utf-8")
                )
            except (OSError, ValueError) as exc:
                raise SensorRegistryError(
                    "Unable to read sensor registry."
                ) from exc

            if (
                not isinstance(data, dict)
                or data.get("version") != 1
                or not isinstance(data.get("sensors"), dict)
            ):
                raise SensorRegistryError(
                    "Invalid sensor registry format."
                )

            self.data = data

    def _sensors(self):
        return self.data["sensors"]

    def _save(self):
        temporary = self.path.with_name(
            self.path.name + ".tmp"
        )
        payload = json.dumps(
            self.data,
            indent=2,
            sort_keys=True
        )

        with temporary.open("w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())

        os.chmod(str(temporary), 0o600)
        os.replace(str(temporary), str(self.path))
        os.chmod(str(self.path), 0o600)

    def _write(self, data):
        self.data = data
        self._save()

    @staticmethod
    def _new_token():
        return secrets.token_urlsafe(32)

    def register(self, sensor_id):
        self._validate_sensor_id(sensor_id)

        with self.lock:
            if sensor_id in self._sensors():
                raise SensorAlreadyExists(
                    "Sensor already registered."
                )

            token = self._new_token()

            self._sensors()[sensor_id] = {
                "token_hash": self._hash_token(token),
                "status": "active",
                "last_seen": None,
            }

            self._save()
            return token

    def verify(self, sensor_id, token):
        if not sensor_id or not token:
            return False

        with self.lock:
            record = self._sensors().get(sensor_id)

            if not record or record.get("status") != "active":
                return False

            supplied_hash = self._hash_token(token)
            expected_hash = record.get("token_hash", "")

            return hmac.compare_digest(
                supplied_hash,
                expected_hash
            )

    def heartbeat(self, sensor_id):
        """Persist the current UTC heartbeat for an active sensor."""
        with self.lock:
            record = self._sensors().get(sensor_id)

            if not record or record.get("status") != "active":
                raise SensorNotFound("Active sensor not found.")

            timestamp = self._timestamp()
            record["last_seen"] = timestamp

            self._save()
            return timestamp

    def rotate(self, sensor_id):
        with self.lock:
            record = self._sensors().get(sensor_id)

            if not record or record.get("status") != "active":
                raise SensorNotFound("Active sensor not found.")

            token = self._new_token()
            record["token_hash"] = self._hash_token(token)

            self._save()
            return token

    def revoke(self, sensor_id):
        with self.lock:
            record = self._sensors().get(sensor_id)

            if not record:
                raise SensorNotFound("Sensor not found.")

            record["status"] = "revoked"
            record["token_hash"] = ""

            self._save()

    def list_sensors(self):
        """Return the existing admin list format for compatibility."""
        with self.lock:
            return [
                {
                    "sensor_id": sensor_id,
                    "status": record["status"],
                }
                for sensor_id, record in sorted(
                    self._sensors().items()
                )
            ]

    def list_sensor_health(self):
        """Return sensor metadata required for health monitoring."""
        with self.lock:
            return [
                {
                    "sensor_id": sensor_id,
                    "status": record["status"],
                    "last_seen": record.get("last_seen"),
                }
                for sensor_id, record in sorted(
                    self._sensors().items()
                )
            ]
