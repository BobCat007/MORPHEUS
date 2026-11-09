# MORPHEUS SOC Dashboard

A React + Vite frontend for exploring honeypot telemetry, sensor health,
investigation data, and Purple Team workflows from the MORPHEUS API.

## Quick start

**Requirements:** Node.js `^20.19.0 || >=22.12.0`, npm, and the
MORPHEUS API running locally.

``` bash
# From the repository root
cd dashboard
npm ci
npm run dev
```

Open **http://127.0.0.1:5173**.

Start the backend separately:

``` bash
# From the repository root
.venv/bin/uvicorn api.app:app --host 127.0.0.1 --port 8000
```

Check API health at `http://127.0.0.1:8000/api/v1/health`.

## What it connects to

| Setting | Value |
|---|---|
| Frontend | `127.0.0.1:5173` |
| API target | `127.0.0.1:8000` |
| API base path | `/api/v1` |
| Live stream | `/api/v1/stream` |
| Vite proxy | `/api` with WebSocket support |

The dashboard uses relative API paths. Vite forwards `/api` requests and
WebSocket traffic to the local backend during development.

## Build, preview, lint

``` bash
npm run build
npm run preview
npm run lint
```

The production build is written to `dist/`. A successful build does not
prove that backend connectivity, authentication, or WebSocket updates
are working.

## Write-token handling

The Vite development proxy can read `MORPHEUS_API_WRITE_TOKEN` and
forward it as `X-Morpheus-Write-Token` for the incident-status `PATCH`
request.

-   Never commit a real token or local environment file.
-   Restrict permissions on files containing secrets.
-   This forwarding behavior is for the Vite development proxy;
    production hosting needs its own deliberate authentication and proxy
    configuration.

## Troubleshooting

-   **Page unavailable:** confirm `npm run dev` is running and port
    `5173` is free.
-   **API errors:** confirm the backend responds at
    `http://127.0.0.1:8000/api/v1/health`.
-   **Live updates missing:** check the `/api/v1/stream` WebSocket
    connection and Vite proxy.
-   **Install errors:** check Node/npm compatibility and ensure the
    lockfile matches `package.json`.

## Validation note

The latest recorded dashboard build succeeded with Vite `8.3.4` in the
development environment. This is a historical validation snapshot, not a
guarantee for every environment.
