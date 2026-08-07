#!/usr/bin/env python3

"""Controlled HTTP honeypot service for Cerberus."""

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime
from hashlib import sha256
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

from cerberus import __version__


PROJECT_ROOT = Path(__file__).resolve().parents[2]

HONEYPOT_DIRECTORY = PROJECT_ROOT / "logs" / "honeypot"
EVENT_LOG_PATH = HONEYPOT_DIRECTORY / "events.jsonl"
PID_PATH = HONEYPOT_DIRECTORY / "honeypot.pid"
SERVICE_LOG_PATH = HONEYPOT_DIRECTORY / "service.log"
EXPORT_STATE_PATH = HONEYPOT_DIRECTORY / "splunk_export_state.json"

DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 8081
MAX_BODY_BYTES = 4096

SENSITIVE_FIELDS = {
    "password",
    "passwd",
    "pass",
    "pwd",
    "secret",
    "token",
    "api_key",
    "apikey",
}


class HoneypotError(RuntimeError):
    """Raised when a Cerberus honeypot action cannot complete."""


def timestamp_now() -> str:
    """Return a timezone-aware event timestamp."""
    return datetime.now().astimezone().isoformat()


def ensure_directories() -> None:
    """Create the honeypot data directory."""
    HONEYPOT_DIRECTORY.mkdir(parents=True, exist_ok=True)


def read_pid() -> int | None:
    """Read the current honeypot worker PID."""
    if not PID_PATH.exists():
        return None

    try:
        return int(PID_PATH.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return None


def process_is_running(pid: int) -> bool:
    """Return whether a local PID currently exists."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True

    return True


def honeypot_status() -> dict[str, Any]:
    """Return the current honeypot process status."""
    pid = read_pid()
    running = bool(pid and process_is_running(pid))

    if pid and not running:
        try:
            PID_PATH.unlink()
        except OSError:
            pass

    return {
        "running": running,
        "pid": pid if running else None,
        "host": DEFAULT_HOST,
        "port": DEFAULT_PORT,
        "event_log": str(EVENT_LOG_PATH),
        "service_log": str(SERVICE_LOG_PATH),
    }


def start_honeypot() -> dict[str, Any]:
    """Start the honeypot as a detached Python process."""
    ensure_directories()

    current_status = honeypot_status()

    if current_status["running"]:
        raise HoneypotError(
            f"Honeypot is already running with PID "
            f"{current_status['pid']}."
        )

    log_handle = SERVICE_LOG_PATH.open(
        "a",
        encoding="utf-8",
    )

    try:
        process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "cerberus.modules.honeypot",
                "--serve",
                "--host",
                DEFAULT_HOST,
                "--port",
                str(DEFAULT_PORT),
            ],
            cwd=PROJECT_ROOT,
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    finally:
        log_handle.close()

    for _ in range(30):
        time.sleep(0.1)
        status = honeypot_status()

        if status["running"]:
            return status

        if process.poll() is not None:
            break

    raise HoneypotError(
        "Honeypot process did not start. "
        f"Review {SERVICE_LOG_PATH}."
    )


def stop_honeypot() -> dict[str, Any]:
    """Stop the background honeypot process."""
    status = honeypot_status()

    if not status["running"]:
        raise HoneypotError("Honeypot is not currently running.")

    pid = int(status["pid"])

    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    except OSError as error:
        raise HoneypotError(
            f"Unable to stop honeypot PID {pid}: {error}"
        ) from error

    for _ in range(40):
        time.sleep(0.1)

        if not process_is_running(pid):
            break

    if process_is_running(pid):
        raise HoneypotError(
            f"Honeypot PID {pid} did not stop cleanly."
        )

    try:
        PID_PATH.unlink()
    except OSError:
        pass

    return honeypot_status()


def redact_form_fields(
    form_data: dict[str, list[str]],
) -> dict[str, Any]:
    """Redact sensitive submitted fields."""
    sanitized: dict[str, Any] = {}

    for key, values in form_data.items():
        normalized_key = key.strip().lower()

        if normalized_key in SENSITIVE_FIELDS:
            sanitized[key] = "[REDACTED]"
            continue

        sanitized[key] = [
            value[:256]
            for value in values[:5]
        ]

    return sanitized


def append_event(event: dict[str, Any]) -> None:
    """Append one interaction event to the JSONL log."""
    ensure_directories()

    with EVENT_LOG_PATH.open(
        "a",
        encoding="utf-8",
    ) as event_file:
        event_file.write(
            json.dumps(event, separators=(",", ":"))
            + "\n"
        )


def event_identifier(event: dict[str, Any]) -> str:
    """Create a stable short identifier for one event."""
    raw_value = json.dumps(
        event,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    return sha256(raw_value).hexdigest()[:16]


def load_honeypot_events(
    limit: int | None = None,
) -> list[dict[str, Any]]:
    """Load locally recorded honeypot events."""
    if not EVENT_LOG_PATH.exists():
        return []

    events: list[dict[str, Any]] = []

    try:
        lines = EVENT_LOG_PATH.read_text(
            encoding="utf-8"
        ).splitlines()
    except OSError as error:
        raise HoneypotError(
            f"Unable to read honeypot event log: {error}"
        ) from error

    if limit is not None:
        lines = lines[-limit:]

    for line in lines:
        if not line.strip():
            continue

        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue

        if isinstance(value, dict):
            events.append(value)

    return events


def honeypot_statistics() -> dict[str, Any]:
    """Create basic statistics from recorded interactions."""
    events = load_honeypot_events()

    source_counts = Counter(
        str(event.get("source_ip", "unknown"))
        for event in events
    )

    method_counts = Counter(
        str(event.get("http_method", "unknown"))
        for event in events
    )

    path_counts = Counter(
        str(event.get("request_path", "unknown"))
        for event in events
    )

    return {
        "total_events": len(events),
        "unique_sources": len(source_counts),
        "top_sources": source_counts.most_common(10),
        "methods": method_counts.most_common(),
        "top_paths": path_counts.most_common(10),
    }


def load_exported_line_count() -> int:
    """Return how many honeypot lines were already exported."""
    if not EXPORT_STATE_PATH.exists():
        return 0

    try:
        data = json.loads(
            EXPORT_STATE_PATH.read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError):
        return 0

    try:
        return max(int(data.get("exported_lines", 0)), 0)
    except (TypeError, ValueError):
        return 0


def save_exported_line_count(count: int) -> None:
    """Persist the last successfully exported line count."""
    ensure_directories()

    EXPORT_STATE_PATH.write_text(
        json.dumps(
            {
                "exported_lines": count,
                "updated_at": timestamp_now(),
            },
            indent=2,
        ),
        encoding="utf-8",
    )


def export_new_events_to_splunk() -> tuple[int, list[str]]:
    """Export only locally recorded events not previously exported."""
    from cerberus.modules.splunk_integration import (
        SplunkIntegrationError,
        load_splunk_config,
        send_event,
    )

    events = load_honeypot_events()
    exported_lines = load_exported_line_count()

    if exported_lines > len(events):
        exported_lines = 0

    new_events = events[exported_lines:]

    if not new_events:
        return 0, []

    try:
        config = load_splunk_config()
    except SplunkIntegrationError as error:
        raise HoneypotError(str(error)) from error

    successful = 0
    errors: list[str] = []

    for event in new_events:
        try:
            response = send_event(
                config,
                event,
                host=str(
                    event.get(
                        "sensor_host",
                        "cerberus-honeypot",
                    )
                ),
            )

            if response.success:
                successful += 1
            else:
                errors.append(response.message)
                break

        except SplunkIntegrationError as error:
            errors.append(str(error))
            break

    if successful:
        save_exported_line_count(
            exported_lines + successful
        )

    return successful, errors


LOGIN_PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Cerberus Gateway Administration</title>
<style>
body {
    font-family: Arial, sans-serif;
    background: #20242a;
    color: #222;
    margin: 0;
}
main {
    width: 360px;
    margin: 12vh auto;
    padding: 28px;
    background: white;
    border-radius: 8px;
}
input {
    box-sizing: border-box;
    width: 100%;
    padding: 10px;
    margin: 7px 0 14px;
}
button {
    width: 100%;
    padding: 11px;
}
small {
    color: #666;
}
</style>
</head>
<body>
<main>
<h2>Gateway Administration</h2>
<p>Sign in to manage this network appliance.</p>
<form method="post" action="/login">
<label>Username</label>
<input name="username" autocomplete="off">
<label>Password</label>
<input name="password" type="password">
<button type="submit">Sign In</button>
</form>
<p><small>Authorized administrators only.</small></p>
</main>
</body>
</html>
"""


FAILED_LOGIN_PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Authentication Failed</title>
</head>
<body>
<h2>Authentication failed</h2>
<p>The supplied administrator credentials were not accepted.</p>
<p><a href="/">Return to sign in</a></p>
</body>
</html>
"""


class CerberusHoneypotHandler(BaseHTTPRequestHandler):
    """HTTP handler that records controlled decoy interactions."""

    server_version = "CerberusGateway/1.0"
    sys_version = ""

    def _client_ip(self) -> str:
        forwarded = self.headers.get("X-Forwarded-For", "")

        if forwarded:
            return forwarded.split(",", 1)[0].strip()

        return str(self.client_address[0])

    def _record_event(
        self,
        *,
        body_fields: dict[str, Any] | None = None,
    ) -> None:
        source_ip = self._client_ip()

        event = {
            "event_type": "honeypot_interaction",
            "application": "cerberus",
            "module": "honeypot",
            "version": __version__,
            "timestamp": timestamp_now(),
            "event_id": "",
            "severity": "medium",
            "service": "http_decoy",
            "sensor_host": "cerberus-honeypot",
            "source_ip": source_ip,
            "source_port": self.client_address[1],
            "destination_port": self.server.server_port,
            "protocol": "tcp",
            "http_method": self.command,
            "request_path": self.path[:1024],
            "user_agent": self.headers.get(
                "User-Agent",
                "",
            )[:1024],
            "host_header": self.headers.get(
                "Host",
                "",
            )[:256],
            "referer": self.headers.get(
                "Referer",
                "",
            )[:1024],
            "submitted_fields": body_fields or {},
        }

        event["event_id"] = event_identifier(event)
        append_event(event)

    def _send_html(
        self,
        status_code: int,
        content: str,
    ) -> None:
        encoded_content = content.encode("utf-8")

        self.send_response(status_code)
        self.send_header(
            "Content-Type",
            "text/html; charset=utf-8",
        )
        self.send_header(
            "Content-Length",
            str(len(encoded_content)),
        )
        self.send_header(
            "Cache-Control",
            "no-store",
        )
        self.end_headers()
        self.wfile.write(encoded_content)

    def do_GET(self) -> None:
        """Record and answer a GET request."""
        self._record_event()

        if self.path in {"/", "/login", "/admin"}:
            self._send_html(200, LOGIN_PAGE)
            return

        self._send_html(
            404,
            "<h2>404 Not Found</h2>",
        )

    def do_HEAD(self) -> None:
        """Record and answer a HEAD request."""
        self._record_event()

        self.send_response(200)
        self.send_header(
            "Content-Type",
            "text/html; charset=utf-8",
        )
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self) -> None:
        """Record a form submission without storing passwords."""
        raw_length = self.headers.get(
            "Content-Length",
            "0",
        )

        try:
            content_length = min(
                int(raw_length),
                MAX_BODY_BYTES,
            )
        except ValueError:
            content_length = 0

        raw_body = self.rfile.read(content_length)
        content_type = self.headers.get(
            "Content-Type",
            "",
        ).lower()

        submitted_fields: dict[str, Any] = {}

        if (
            "application/x-www-form-urlencoded"
            in content_type
        ):
            decoded_body = raw_body.decode(
                "utf-8",
                errors="replace",
            )

            submitted_fields = redact_form_fields(
                parse_qs(
                    decoded_body,
                    keep_blank_values=True,
                )
            )
        elif raw_body:
            submitted_fields = {
                "body_present": True,
                "body_size": len(raw_body),
                "body_content": "[NOT STORED]",
            }

        self._record_event(
            body_fields=submitted_fields,
        )

        self._send_html(401, FAILED_LOGIN_PAGE)

    def log_message(
        self,
        format_string: str,
        *arguments: Any,
    ) -> None:
        """Suppress default console request logs."""
        return


def run_worker(host: str, port: int) -> None:
    """Run the honeypot worker until terminated."""
    ensure_directories()

    existing_status = honeypot_status()

    if existing_status["running"]:
        raise HoneypotError(
            "Another honeypot worker is already running."
        )

    should_stop = False

    def request_stop(
        signum: int,
        frame: Any,
    ) -> None:
        nonlocal should_stop
        should_stop = True

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)

    try:
        server = ThreadingHTTPServer(
            (host, port),
            CerberusHoneypotHandler,
        )
    except OSError as error:
        raise HoneypotError(
            f"Unable to bind honeypot to "
            f"{host}:{port}: {error}"
        ) from error

    server.timeout = 1.0

    PID_PATH.write_text(
        str(os.getpid()),
        encoding="utf-8",
    )

    print(
        f"[{timestamp_now()}] Cerberus honeypot listening "
        f"on {host}:{port}",
        flush=True,
    )

    try:
        while not should_stop:
            server.handle_request()
    finally:
        server.server_close()

        try:
            PID_PATH.unlink()
        except OSError:
            pass

        print(
            f"[{timestamp_now()}] Cerberus honeypot stopped",
            flush=True,
        )


def build_argument_parser() -> argparse.ArgumentParser:
    """Create the worker command-line parser."""
    parser = argparse.ArgumentParser(
        description="Cerberus HTTP Honeypot",
    )

    parser.add_argument(
        "--serve",
        action="store_true",
        help="Run the honeypot worker",
    )
    parser.add_argument(
        "--host",
        default=DEFAULT_HOST,
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
    )

    return parser


def main() -> int:
    """Run the requested honeypot command."""
    arguments = build_argument_parser().parse_args()

    if not arguments.serve:
        print(honeypot_status())
        return 0

    try:
        run_worker(
            arguments.host,
            arguments.port,
        )
    except HoneypotError as error:
        print(f"[!] {error}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
