"""Run the isolated MORPHEUS HTTP deception service."""

import os

import uvicorn

from telemetry.http.app import create_http_app


def main():
    storage_path = os.environ.get("MORPHEUS_HTTP_EVENT_STORE")

    if not storage_path:
        raise SystemExit(
            "Set MORPHEUS_HTTP_EVENT_STORE to an isolated JSONL path."
        )

    app = create_http_app(storage_path)

    uvicorn.run(
        app,
        host=os.getenv("MORPHEUS_HTTP_HOST", "127.0.0.1"),
        port=int(os.getenv("MORPHEUS_HTTP_PORT", "8080")),
    )


if __name__ == "__main__":
    main()
