import os
import re
import tempfile
from configparser import ConfigParser
from pathlib import Path
from typing import Dict, List, Optional

from deception.control.adapter import DeceptionAdapter
from deception.control.model import DeceptionPlan


class CowrieAdapter(DeceptionAdapter):
    """Apply supported identity settings to Cowrie without discarding config."""

    # Representative Ubuntu 22.04 fingerprints, not an exact OS fingerprint.
    # Cowrie uses separate settings for the SSH wire banner and `ssh -V`.
    _OS_FINGERPRINTS: Dict[str, Dict[str, str]] = {
        "ubuntu 22.04": {
            "kernel_version": "5.15.0-91-generic",
            "kernel_build_string": (
                "#101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023"
            ),
            "hardware_platform": "x86_64",
            "operating_system": "GNU/Linux",
            "ssh_version": (
                "OpenSSH_8.9p1, OpenSSL 3.0.2 15 Mar 2022"
            ),
            "ssh_protocol_version": (
                "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"
            ),
        },
    }

    def __init__(self, config_path: str) -> None:
        self.config_path = Path(config_path)

    @staticmethod
    def _set_option(
        lines: List[str],
        section_name: str,
        option_name: str,
        value: str,
    ) -> List[str]:
        """Set one INI option while preserving unrelated lines and comments."""
        section_pattern = re.compile(
            r"^\s*\[([^\]]+)\]\s*(?:[#;].*)?$"
        )
        option_pattern = re.compile(
            r"^\s*" + re.escape(option_name) + r"\s*=",
            re.IGNORECASE,
        )

        section_start: Optional[int] = None
        section_end = len(lines)

        for index, line in enumerate(lines):
            match = section_pattern.match(line.rstrip("\r\n"))
            if not match:
                continue

            if section_start is not None:
                section_end = index
                break

            if match.group(1).strip().lower() == section_name.lower():
                section_start = index

        replacement = "{} = {}\n".format(option_name, value)

        if section_start is None:
            if lines and not lines[-1].endswith(("\n", "\r")):
                lines[-1] += "\n"
            if lines and lines[-1].strip():
                lines.append("\n")
            lines.extend(
                ["[{}]\n".format(section_name), replacement]
            )
            return lines

        for index in range(section_start + 1, section_end):
            if option_pattern.match(lines[index].rstrip("\r\n")):
                indentation = lines[index][
                    :len(lines[index]) - len(lines[index].lstrip())
                ]
                lines[index] = indentation + replacement
                return lines

        lines.insert(section_end, replacement)
        return lines

    def _write_config(self, lines: List[str]) -> None:
        """Atomically replace the config after preparing the new contents."""
        self.config_path.parent.mkdir(parents=True, exist_ok=True)

        existing_mode = (
            self.config_path.stat().st_mode & 0o777
            if self.config_path.exists()
            else 0o644
        )

        descriptor, temporary_path = tempfile.mkstemp(
            prefix=self.config_path.name + ".",
            suffix=".tmp",
            dir=str(self.config_path.parent),
        )

        try:
            with os.fdopen(
                descriptor, "w", encoding="utf-8", newline=""
            ) as handle:
                handle.writelines(lines)
                handle.flush()
                os.fsync(handle.fileno())

            os.chmod(temporary_path, existing_mode)
            os.replace(temporary_path, str(self.config_path))
        except Exception:
            try:
                os.unlink(temporary_path)
            except OSError:
                pass
            raise

    def apply(self, plan: DeceptionPlan) -> None:
        """Apply hostname and known OS/SSH identity settings to Cowrie."""
        if (
            not plan.hostname
            or "\n" in plan.hostname
            or "\r" in plan.hostname
        ):
            raise ValueError(
                "A valid, single-line hostname is required."
            )

        lines = (
            self.config_path.read_text(encoding="utf-8").splitlines(True)
            if self.config_path.exists()
            else []
        )

        lines = self._set_option(
            lines, "honeypot", "hostname", plan.hostname
        )

        fingerprint = self._OS_FINGERPRINTS.get(
            plan.operating_system.strip().lower()
        )

        if fingerprint:
            for option in (
                "kernel_version",
                "kernel_build_string",
                "hardware_platform",
                "operating_system",
                "ssh_version",
            ):
                lines = self._set_option(
                    lines, "shell", option, fingerprint[option]
                )

            lines = self._set_option(
                lines,
                "ssh",
                "version",
                fingerprint["ssh_protocol_version"],
            )

        self._write_config(lines)

    def current_state(self) -> DeceptionPlan:
        """Return the hostname currently configured in Cowrie."""
        config = ConfigParser(interpolation=None)

        if self.config_path.exists():
            config.read(str(self.config_path), encoding="utf-8")

        hostname = config.get(
            "honeypot", "hostname", fallback="unknown"
        )

        return DeceptionPlan(
            personality_name="unknown",
            hostname=hostname,
            operating_system="unknown",
            deception_level=0,
        )
