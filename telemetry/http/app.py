"""Isolated HTTP deception service for MORPHEUS."""

import os
import time
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse

from core.events.bus import EventBus
from core.events.model import MorpheusEvent
from core.storage.event_store import EventStore
from core.storage.handler import EventStorageHandler


HTTP_EVENT_TYPE = "morpheus.http.request"


def create_http_app(storage_path: str) -> FastAPI:
    """Create an isolated HTTP honeypot with its own event store."""

    if not storage_path:
        raise ValueError("An explicit HTTP event-store path is required.")

    store_path = Path(storage_path).resolve()

    event_bus = EventBus()
    event_store = EventStore(str(store_path))
    storage_handler = EventStorageHandler(event_store)

    event_bus.subscribe(HTTP_EVENT_TYPE, storage_handler.handle)

    app = FastAPI(
        title="MORPHEUS HTTP Deception",
        docs_url=None,
        redoc_url=None,
    )

    @app.middleware("http")
    async def capture_http_activity(request: Request, call_next):
        started = time.perf_counter()
        status_code = 500

        try:
            response = await call_next(request)
            status_code = response.status_code
            return response
        finally:
            elapsed_ms = round(
                (time.perf_counter() - started) * 1000, 2
            )

            client_ip = (
                request.client.host
                if request.client is not None
                else None
            )

            event = MorpheusEvent(
                event_type=HTTP_EVENT_TYPE,
                source="morpheus.http",
                data={
                    "honeypot_id": os.getenv(
                        "MORPHEUS_HONEYPOT_ID", "http-default"
                    ),
                    "client_ip": client_ip,
                    "method": request.method,
                    "path": request.url.path,
                    "user_agent": request.headers.get("user-agent"),
                    "content_type": request.headers.get("content-type"),
                    "status_code": status_code,
                    "response_time_ms": elapsed_ms,
                },
            )

            event_bus.publish(event)

    @app.get("/", response_class=HTMLResponse)
    async def homepage():
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Enterprise Portal</title>
            <meta charset="utf-8">
        </head>
        <body>
            <h1>Enterprise Application Portal</h1>
            <p>Internal application services</p>
            <ul>
                <li><a href="/login">Employee Login</a></li>
                <li><a href="/dashboard">Application Dashboard</a></li>
                <li><a href="/admin">Administration</a></li>
            </ul>
        </body>
        </html>
        """

    @app.get("/login", response_class=HTMLResponse)
    async def login_page():
        return """
        <!DOCTYPE html>
        <html>
        <head><title>Employee Login</title></head>
        <body>
            <h1>Employee Portal</h1>
            <p>Authentication service is available for demonstration.</p>
        </body>
        </html>
        """

    @app.get("/dashboard", response_class=HTMLResponse)
    async def dashboard():
        return """
        <html>
        <head><title>Application Dashboard</title></head>
        <body>
            <h1>Application Dashboard</h1>
            <p>Enterprise application services are operational.</p>
        </body>
        </html>
        """

    @app.get("/admin", response_class=HTMLResponse)
    async def admin_page():
        return """
        <html>
        <head><title>Administration</title></head>
        <body>
            <h1>Administration Portal</h1>
            <p>Restricted enterprise administration interface.</p>
        </body>
        </html>
        """

    @app.get("/health")
    async def health():
        return JSONResponse({"status": "healthy"})

    return app
