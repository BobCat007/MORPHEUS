import re
from typing import List

from intelligence.session.model import ReconstructedSession
from threat_intel.ioc.model import IOC


class IOCExtractor:
    """Extract indicators of compromise from attacker sessions."""

    IPV4_PATTERN = re.compile(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    )

    DOMAIN_PATTERN = re.compile(
        r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"
    )

    URL_PATTERN = re.compile(
        r"https?://[^\s\"'<>]+"
    )

    SHA256_PATTERN = re.compile(
        r"\b[a-fA-F0-9]{64}\b"
    )

    MD5_PATTERN = re.compile(
        r"\b[a-fA-F0-9]{32}\b"
    )

    def extract(
        self,
        session: ReconstructedSession,
    ) -> List[IOC]:
        """Extract IOCs from all commands in a session."""

        iocs: List[IOC] = []

        for command in session.commands:
            iocs.extend(
                self._extract_from_command(
                    command,
                    session.session_id,
                )
            )

        return self._deduplicate(iocs)

    def _extract_from_command(
        self,
        command: str,
        session_id: str,
    ) -> List[IOC]:
        """Extract all supported IOC types from one command."""

        iocs: List[IOC] = []

        urls = self.URL_PATTERN.findall(command)

        for url in urls:
            iocs.append(
                IOC(
                    value=url,
                    ioc_type="url",
                    source="cowrie",
                    session_id=session_id,
                    context=[command],
                )
            )

        sha256_hashes = self.SHA256_PATTERN.findall(command)

        for value in sha256_hashes:
            iocs.append(
                IOC(
                    value=value,
                    ioc_type="sha256",
                    source="cowrie",
                    session_id=session_id,
                    context=[command],
                )
            )

        md5_hashes = self.MD5_PATTERN.findall(command)

        for value in md5_hashes:
            iocs.append(
                IOC(
                    value=value,
                    ioc_type="md5",
                    source="cowrie",
                    session_id=session_id,
                    context=[command],
                )
            )

        ipv4_addresses = self.IPV4_PATTERN.findall(command)

        for value in ipv4_addresses:
            if self._is_valid_ipv4(value):
                iocs.append(
                    IOC(
                        value=value,
                        ioc_type="ipv4",
                        source="cowrie",
                        session_id=session_id,
                        context=[command],
                    )
                )

        domains = self.DOMAIN_PATTERN.findall(command)

        for value in domains:
            if not self._is_ip_address(value):
                iocs.append(
                    IOC(
                        value=value,
                        ioc_type="domain",
                        source="cowrie",
                        session_id=session_id,
                        context=[command],
                    )
                )

        return iocs

    def _is_valid_ipv4(self, value: str) -> bool:
        """Validate an IPv4 address."""

        parts = value.split(".")

        if len(parts) != 4:
            return False

        return all(
            part.isdigit() and 0 <= int(part) <= 255
            for part in parts
        )

    def _is_ip_address(self, value: str) -> bool:
        """Return True when a value is an IPv4 address."""

        return self.IPV4_PATTERN.fullmatch(value) is not None

    def _deduplicate(self, iocs: List[IOC]) -> List[IOC]:
        """Remove duplicate IOCs while preserving first occurrence."""

        unique = {}
        
        for ioc in iocs:
            key = (ioc.ioc_type, ioc.value)

            if key not in unique:
                unique[key] = ioc
            else:
                for evidence in ioc.context:
                    unique[key].add_context(evidence)

        return list(unique.values())
