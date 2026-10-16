import posixpath
import re
import shlex
from typing import List, Optional
from urllib.parse import unquote, urlsplit

from intelligence.intent.model import IntentResult


class CommandSequenceDetector:
    """Detect download-to-execution chains using command evidence."""

    DOWNLOAD_COMMANDS = {"wget", "curl"}
    INTERPRETERS = {"bash", "sh", "python", "python3", "perl"}

    PIPE_TO_EXECUTOR = re.compile(
        r"\|\s*(?:sudo\s+)?(?:bash|sh|python(?:3)?|perl)\b",
        re.IGNORECASE,
    )

    def detect(
        self,
        commands: Optional[List[str]],
    ) -> Optional[IntentResult]:
        """Find a direct pipeline or a download followed by matching execution."""

        if not commands:
            return None

        evidence: List[str] = []

        # Direct download-to-interpreter pipelines.
        for command in commands:
            normalized = command.strip()
            if (
                self._command_name(normalized) in self.DOWNLOAD_COMMANDS
                and self.PIPE_TO_EXECUTOR.search(normalized)
            ):
                self._add_evidence(evidence, command)

        # A downloaded file must match the file later launched.
        for index, command in enumerate(commands):
            target = self._download_target(command)
            if target is None:
                continue

            for later_index in range(index + 1, len(commands)):
                later_command = commands[later_index]
                launched_target = self._launch_target(later_command)

                if launched_target != target:
                    continue

                self._add_evidence(evidence, command)

                # Include chmod only when it refers to the same file.
                for middle_command in commands[index + 1:later_index]:
                    if self._chmod_target(middle_command) == target:
                        self._add_evidence(evidence, middle_command)

                self._add_evidence(evidence, later_command)
                break

        if not evidence:
            return None

        return IntentResult(
            intent="payload_execution_chain",
            confidence=0.85,
            evidence=evidence,
            phase="execution",
        )

    @staticmethod
    def _tokens(command: str) -> List[str]:
        try:
            tokens = shlex.split(command)
        except ValueError:
            return []

        while tokens and tokens[0] == "sudo":
            tokens = tokens[1:]

        return tokens

    @classmethod
    def _command_name(cls, command: str) -> Optional[str]:
        tokens = cls._tokens(command)
        if not tokens:
            return None

        return posixpath.basename(tokens[0]).lower()

    @staticmethod
    def _normalize_target(target: Optional[str]) -> Optional[str]:
        if not target or target.startswith("-"):
            return None

        normalized = posixpath.normpath(target)
        if normalized in {"", "."}:
            return None

        return normalized

    @classmethod
    def _download_target(cls, command: str) -> Optional[str]:
        tokens = cls._tokens(command)
        if not tokens:
            return None

        downloader = posixpath.basename(tokens[0]).lower()
        if downloader not in cls.DOWNLOAD_COMMANDS:
            return None

        output_target = None
        remote_name = False
        url = None
        index = 1

        while index < len(tokens):
            token = tokens[index]

            if downloader == "wget":
                if token in {"-O", "--output-document"}:
                    if index + 1 < len(tokens):
                        output_target = tokens[index + 1]
                        index += 2
                        continue
                elif token.startswith("--output-document="):
                    output_target = token.split("=", 1)[1]
                elif token.startswith("-O") and token != "-O":
                    output_target = token[2:]

            if downloader == "curl":
                if token in {"-o", "--output"}:
                    if index + 1 < len(tokens):
                        output_target = tokens[index + 1]
                        index += 2
                        continue
                elif token.startswith("--output="):
                    output_target = token.split("=", 1)[1]
                elif token.startswith("-o") and token != "-o":
                    output_target = token[2:]
                elif token == "-O":
                    remote_name = True

            if token.lower().startswith(("http://", "https://", "ftp://")):
                url = token

            index += 1

        if output_target:
            return cls._normalize_target(output_target)

        if url:
            filename = unquote(posixpath.basename(urlsplit(url).path))
            if filename:
                return cls._normalize_target(filename)

        return None

    @classmethod
    def _launch_target(cls, command: str) -> Optional[str]:
        tokens = cls._tokens(command)
        if not tokens:
            return None

        executable = posixpath.basename(tokens[0]).lower()

        if tokens[0].startswith("./") or tokens[0].startswith("/"):
            return cls._normalize_target(tokens[0])

        if executable not in cls.INTERPRETERS:
            return None

        # Avoid treating interpreter options such as `python -c` as files.
        for token in tokens[1:]:
            if token == "--":
                continue
            if token.startswith("-"):
                return None
            return cls._normalize_target(token)

        return None

    @classmethod
    def _chmod_target(cls, command: str) -> Optional[str]:
        tokens = cls._tokens(command)
        if not tokens or posixpath.basename(tokens[0]).lower() != "chmod":
            return None

        operands = [token for token in tokens[1:] if not token.startswith("-")]
        if len(operands) < 2:
            return None

        return cls._normalize_target(operands[-1])

    @staticmethod
    def _add_evidence(evidence: List[str], command: str) -> None:
        if command not in evidence:
            evidence.append(command)
