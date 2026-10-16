"""Command-line interface for MORPHEUS."""

import argparse
import sys
from typing import Optional, Sequence

from reporting.service import generate_incident_report_from_store


def build_parser() -> argparse.ArgumentParser:
    """Build the MORPHEUS command-line argument parser."""

    parser = argparse.ArgumentParser(
        prog="morpheus",
        description="MORPHEUS — Adaptive Adversary Deception & Intelligence",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    report_parser = subparsers.add_parser(
        "report",
        help="Generate an incident report from stored analysis events.",
        description="Generate a JSON incident report for a stored session.",
    )

    report_parser.add_argument(
        "--storage-path",
        required=True,
        help="Path to the JSONL event store.",
    )
    report_parser.add_argument(
        "--session-id",
        required=True,
        help="Session ID to generate the incident report for.",
    )
    report_parser.add_argument(
        "--output",
        required=True,
        help="Destination path for the JSON incident report.",
    )
    report_parser.add_argument(
        "--generated-at",
        default=None,
        help="Optional report-generation timestamp in ISO 8601 format.",
    )

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run the requested MORPHEUS CLI command."""

    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "report":
        try:
            report = generate_incident_report_from_store(
                storage_path=args.storage_path,
                session_id=args.session_id,
                output_path=args.output,
                generated_at=args.generated_at,
            )
        except (LookupError, ValueError, OSError) as exc:
            print("Error: {}".format(exc), file=sys.stderr)
            return 1

        session = report.get("session", {})
        reported_session_id = (
            session.get("session_id", args.session_id)
            if isinstance(session, dict)
            else args.session_id
        )

        print("Incident report generated successfully.")
        print("Session ID: {}".format(reported_session_id))
        print("Output: {}".format(args.output))
        return 0

    parser.error("Unsupported command.")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
