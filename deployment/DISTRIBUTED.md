# MORPHEUS Distributed Honeynet Deployment

## 1. Architecture

A distributed deployment separates collection from analysis.

Remote honeypot:
    Cowrie JSON log
        -> MORPHEUS sensor process
        -> persistent local delivery queue
        -> authenticated HTTPS requests

Central server:
    MORPHEUS API collector
        -> data/sensor-events.jsonl
        -> central analysis worker
        -> data/events.jsonl
        -> dashboard and reporting API

The sensor queue is retained until the collector acknowledges events.
The collector deduplicates event IDs in persistent storage.
The analysis worker maintains separate session contexts for each sensor.

## 2. Requirements

Central server:
- Linux with systemd
- Python environment and project dependencies installed
- MORPHEUS repository
- A persistent writable data directory
- HTTPS reverse proxy or private VPN access for remote sensors

Each sensor host:
- Linux with systemd
- Python environment and MORPHEUS source/dependencies
- Cowrie running locally
- Read access to the Cowrie JSON log
- Outbound connectivity to the central collector
- A persistent writable sensor queue directory

The service templates currently use:
    User=ubuntu
    Group=ubuntu
    WorkingDirectory=/home/ubuntu/morpheus

Change these values on hosts that use a different account or installation path.

## 3. Central server configuration

Create the service configuration directory:

    sudo install -d -m 700 /etc/morpheus

Create the data directory:

    mkdir -p /home/ubuntu/morpheus/data
    chmod 700 /home/ubuntu/morpheus/data

Install the API environment file:

    sudo install -m 600 deployment/systemd/api.env.example /etc/morpheus/api.env

Edit it:

    sudoedit /etc/morpheus/api.env

Set a unique, long random value for MORPHEUS_SENSOR_ADMIN_TOKEN.
Do not commit the real environment file or place secrets in Git.

Install the service units:

    sudo cp deployment/systemd/morpheus-api.service /etc/systemd/system/
    sudo cp deployment/systemd/morpheus-analysis-worker.service /etc/systemd/system/

Reload systemd:

    sudo systemctl daemon-reload

Start the API:

    sudo systemctl enable --now morpheus-api

Check:

    sudo systemctl status morpheus-api
    curl http://127.0.0.1:8000/api/v1/health

Expected health response:

    {"status":"ok","service":"morpheus-api"}

The API binds to localhost intentionally. Put it behind a TLS reverse proxy
or expose it only through a trusted VPN. Do not expose port 8000 directly
to untrusted networks.

## 4. Register a sensor

Sensor registration is an administrator operation.

The endpoint is:

    POST /api/v1/sensors

It requires:

    X-Morpheus-Sensor-Admin-Token

Example request (replace the hostname and secret):

    curl --fail-with-body https://collector.example.org/api/v1/sensors \
      -H "Content-Type: application/json" \
      -H "X-Morpheus-Sensor-Admin-Token: YOUR_ADMIN_SECRET" \
      -d '{"sensor_id":"site-a"}'

The response contains a newly generated sensor token.
The token is displayed only once. Store it securely on the corresponding
sensor host. Never put it in source control, documentation, or logs.

The sensor ID must be unique and use letters, digits, dots, underscores,
or hyphens.

## 5. Configure a remote sensor

On each sensor host, create the configuration directory:

    sudo install -d -m 700 /etc/morpheus
    sudo install -d -m 700 /var/lib/morpheus

Install the environment template:

    sudo install -m 600 deployment/systemd/sensor.env.example /etc/morpheus/sensor.env

Edit the file:

    sudoedit /etc/morpheus/sensor.env

Set:
- MORPHEUS_COLLECTOR_URL to the central HTTPS collector URL
- MORPHEUS_SENSOR_ID to the registered sensor ID
- MORPHEUS_COWRIE_LOG to the actual local Cowrie JSON log
- MORPHEUS_SENSOR_QUEUE to a persistent writable queue path

Create the token file without putting the token in shell history:

    read -rsp "Paste sensor token: " MORPHEUS_TOKEN
    echo
    printf '%s' "$MORPHEUS_TOKEN" | sudo tee /etc/morpheus/sensor.token >/dev/null
    unset MORPHEUS_TOKEN
    sudo chmod 600 /etc/morpheus/sensor.token

The service account must be able to read the Cowrie log and token file,
and write to /var/lib/morpheus.

Install the sensor unit:

    sudo cp deployment/systemd/morpheus-sensor.service /etc/systemd/system/
    sudo systemctl daemon-reload
    sudo systemctl enable --now morpheus-sensor

Check:

    sudo systemctl status morpheus-sensor
    sudo journalctl -u morpheus-sensor -f

Repeat this configuration for every independent honeypot sensor.
Use a unique sensor ID and token for each one.

## 6. Start central analysis

On the central server:

    sudo systemctl enable --now morpheus-analysis-worker

Check:

    sudo systemctl status morpheus-analysis-worker
    sudo journalctl -u morpheus-analysis-worker -f

The worker reads:

    data/sensor-events.jsonl

It writes analysis events to:

    data/events.jsonl

It creates an independent intelligence context per sensor.
Adaptive deception is disabled in this central analysis worker.

## 7. Monitoring

API health:

    curl http://127.0.0.1:8000/api/v1/health

Sensor health (through the central API):

    curl https://collector.example.org/api/v1/sensors/health

Administrator sensor listing:

    curl https://collector.example.org/api/v1/sensors \
      -H "X-Morpheus-Sensor-Admin-Token: YOUR_ADMIN_SECRET"

Logs:

    sudo journalctl -u morpheus-api -f
    sudo journalctl -u morpheus-analysis-worker -f
    sudo journalctl -u morpheus-sensor -f

The sensor health endpoint uses the configured heartbeat timeout.
The default is 90 seconds; the sensor heartbeat interval defaults to 30 seconds.

## 8. Credential operations

Rotate a sensor token:

    POST /api/v1/sensors/{sensor_id}/rotate

Revoke a sensor:

    DELETE /api/v1/sensors/{sensor_id}

Both operations require the administrator header.
A rotated token must replace the old token file on the sensor host.
A revoked sensor can no longer authenticate.

## 9. Recovery and persistence

The sensor queue is stored separately from the Cowrie log.
Do not put it in /tmp or another volatile directory.

The collector acknowledges accepted and duplicate event IDs.
The sensor removes acknowledged events from its queue.
Unacknowledged events remain available for retry.

The central worker replays stored sensor events after restart and restores
previously analyzed session IDs from the analysis event store.

Back up:
- data/sensor-events.jsonl
- data/events.jsonl
- data/sensor-registry.json
- sensor token files, stored securely
- each sensor's persistent queue

Protect backups because they contain security telemetry and credentials
or credential hashes.

## 10. Troubleshooting

Sensor cannot start:
- Check the token file exists and is readable by the service user.
- Check the Cowrie JSON log path exists and is readable.
- Check the sensor environment file and collector URL.
- Inspect journalctl output.

Sensor reports authentication errors:
- Verify sensor ID and token match the central registry.
- Check whether the token was rotated or the sensor revoked.
- Verify the collector URL reaches the correct API.

Sensor appears offline:
- Check network connectivity and TLS certificate validity.
- Check the sensor heartbeat interval and central timeout.
- Inspect both sensor and API logs.

Analysis is not appearing:
- Confirm morpheus-analysis-worker is running.
- Confirm both services use the same sensor event store and analysis output paths.
- Inspect worker logs for JSONL parsing or storage errors.

Do not disable TLS verification to work around certificate errors.
Fix the certificate chain or use a trusted VPN.
