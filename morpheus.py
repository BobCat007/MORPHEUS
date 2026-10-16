
"""Command-line interface for MORPHEUS."""

import argparse
import sys
from typing import Optional, Sequence

from incidents.service import (
    VALID_STATUSES,
    get_incident,
    list_incidents,
    update_incident_status,
)
from reporting.service import generate_incident_report_from_store


def build_parser() -> argparse.ArgumentParser:
    """Build the MORPHEUS command-line argument parser."""

    parser = argparse.ArgumentParser(
        prog="morpheus",
        description="MORPHEUS — Adaptive Adversary Deception & Intelligence",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    report_parser = subparsers.add_parser(
        "report",
        help="Generate an incident report from stored analysis events.",
        description="Generate a JSON incident report for a stored session.",
    )
    report_parser.add_argument("--storage-path", required=True)
    report_parser.add_argument("--session-id", required=True)
    report_parser.add_argument("--output", required=True)
    report_parser.add_argument("--generated-at", default=None)

    incidents_parser = subparsers.add_parser(
        "incidents",
        help="Manage security incidents.",
    )
    incident_commands = incidents_parser.add_subparsers(
        dest="incident_command",
        required=True,
    )

    list_parser = incident_commands.add_parser(
        "list",
        help="List incidents.",
    )
    list_parser.add_argument("--storage-path", required=True)

    show_parser = incident_commands.add_parser(
        "show",
        help="Show an incident and its history.",
    )
    show_parser.add_argument("--storage-path", required=True)
    show_parser.add_argument("--incident-id", required=True)

    status_parser = incident_commands.add_parser(
        "status",
        help="Change an incident's status.",
    )
    status_parser.add_argument("--storage-path", required=True)
    status_parser.add_argument("--incident-id", required=True)
    status_parser.add_argument(
        "--status",
        required=True,
        choices=VALID_STATUSES,
    )
    status_parser.add_argument("--actor", default="analyst")
    status_parser.add_argument("--note", default=None)

    return parser


def _print_incident(incident) -> None:
    """Print incident details and the status audit history."""

    print("Incident ID: {}".format(incident["incident_id"]))
    print("Alert ID: {}".format(incident["alert_id"]))
    print("Session ID: {}".format(incident.get("session_id")))
    print("Severity: {}".format(incident.get("severity")))
    print("Risk score: {}".format(incident.get("risk_score")))
    print("Source IP: {}".format(incident.get("source_ip")))
    print("Status: {}".format(incident["status"]))
    print("Created at: {}".format(incident.get("created_at")))
    print("Updated at: {}".format(incident.get("updated_at")))
    print("Title: {}".format(incident.get("title")))
    print("Description: {}".format(incident.get("description")))

    history = incident.get("history", [])
    print("Status history:")
    if not history:
        print("  No status changes recorded.")
        return

    for entry in history:
        print(
            "  {timestamp}: {old} -> {new} by {actor}".format(
                timestamp=entry.get("timestamp", ""),
                old=entry.get("from_status", ""),
                new=entry.get("to_status", ""),
                actor=entry.get("actor", "analyst"),
            )
        )
        if entry.get("note"):
            print("    Note: {}".format(entry["note"]))


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run the requested MORPHEUS CLI command."""

    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "report":
            report = generate_incident_report_from_store(
                storage_path=args.storage_path,
                session_id=args.session_id,
                output_path=args.output,
                generated_at=args.generated_at,
            )

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

        if args.command == "incidents":
            if args.incident_command == "list":
                incidents = list_incidents(args.storage_path)
                if not incidents:
                    print("No incidents found.")
                    return 0

                for incident in incidents:
                    print(
                        "{id} | {severity} | {status} | session={session}".format(
                            id=incident["incident_id"],
                            severity=incident.get("severity", "unknown"),
                            status=incident["status"],
                            session=incident.get("session_id"),
                        )
                    )
                print("Total incidents: {}".format(len(incidents)))
                return 0

            if args.incident_command == "show":
                _print_incident(
                    get_incident(args.storage_path, args.incident_id)
                )
                return 0

            if args.incident_command == "status":
                incident = update_incident_status(
                    storage_path=args.storage_path,
                    incident_id=args.incident_id,
                    status=args.status,
                    actor=args.actor,
                    note=args.note,
                )
                print("Incident status updated successfully.")
                print("Incident ID: {}".format(incident["incident_id"]))
                print("Status: {}".format(incident["status"]))
                return 0

    except (LookupError, ValueError, OSError) as exc:
        print("Error: {}".format(exc), file=sys.stderr)
        return 1

    parser.error("Unsupported command.")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
