from pathlib import Path
from threading import Event
import logging
import sys

PROJECT_DIR = Path.home() / "morpheus"

# Ensure the MORPHEUS project root is importable when launched by systemd.
sys.path.insert(0, str(PROJECT_DIR))

from telemetry.cowrie.live_pipeline import run_live_cowrie_pipeline

LOG_PATH = Path.home() / "morpheus-test/var/log/cowrie/cowrie.json"
STORAGE_PATH = PROJECT_DIR / "data/events.jsonl"


def main():
    if not LOG_PATH.is_file():
        print(f"ERROR: Test Cowrie log not found: {LOG_PATH}", file=sys.stderr)
        return 1

    if not LOG_PATH.stat().st_mode & 0o444:
        print(f"ERROR: Test Cowrie log has no read permission bits: {LOG_PATH}", file=sys.stderr)
        return 1

    stop_event = Event()

    print(f"Following isolated test log: {LOG_PATH}", flush=True)
    print(f"Writing MORPHEUS events to: {STORAGE_PATH}", flush=True)
    print("Adaptive deception: DISABLED", flush=True)

    try:
        run_live_cowrie_pipeline(
            log_path=str(LOG_PATH),
            storage_path=str(STORAGE_PATH),
            stop_event=stop_event,
            poll_interval=0.25,
            start_at_end=True,
            adaptive_deception_enabled=False,
            alert_minimum_severity="high",
        )
    except KeyboardInterrupt:
        stop_event.set()
    except Exception:
        logging.exception("MORPHEUS test ingestion pipeline failed")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
