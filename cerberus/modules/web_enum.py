#!/usr/bin/env python3

from __future__ import annotations

import http.client
import ipaddress
import json
import socket
import ssl
from dataclasses import asdict, dataclass
from datetime import datetime
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin
from urllib.request import (
    HTTPRedirectHandler,
    Request,
    build_opener,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]
WEB_SCAN_DIRECTORY = PROJECT_ROOT / "scans" / "web"

WEB_PORTS = {
    80: "http",
    443: "https",
    8000: "http",
    8080: "http",
    8443: "https",
}

SECURITY_HEADERS = {
    "content-security-policy": "Content-Security-Policy",
    "strict-transport-security": "Strict-Transport-Security",
    "x-content-type-options": "X-Content-Type-Options",
    "x-frame-options": "X-Frame-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
}


class WebEnumerationError(RuntimeError):
    """Raised when web enumeration cannot be completed."""


class TitleParser(HTMLParser):
    """Extract the first HTML title element."""

    def __init__(self) -> None:
        super().__init__()
        self.in_title = False
        self.title_parts: list[str] = []

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        if tag.lower() == "title":
            self.in_title = True

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self.in_title = False

    def handle_data(self, data: str) -> None:
        if self.in_title:
            self.title_parts.append(data.strip())

    @property
    def title(self) -> str:
        return " ".join(
            part for part in self.title_parts if part
        ).strip()


@dataclass
class TLSCertificate:
    subject: str = ""
    issuer: str = ""
    serial_number: str = ""
    not_before: str = ""
    not_after: str = ""
    protocol: str = ""
    cipher: str = ""


@dataclass
class WebServiceResult:
    scheme: str
    port: int
    requested_url: str
    final_url: str
    status_code: int
    reason: str
    title: str
    server: str
    content_type: str
    content_length: str
    headers: dict[str, str]
    present_security_headers: list[str]
    missing_security_headers: list[str]
    robots_status: int | None
    robots_preview: str
    tls: TLSCertificate | None
    error: str = ""


@dataclass
class WebEnumerationResult:
    timestamp: str
    target: str
    service_count: int
    services: list[WebServiceResult]


class LimitedRedirectHandler(HTTPRedirectHandler):
    """Use normal redirects while keeping enumeration predictable."""

    max_redirections = 5


def validate_target(target: str) -> str:
    """Validate one IPv4 target."""
    try:
        address = ipaddress.ip_address(target)
    except ValueError as error:
        raise WebEnumerationError(
            f"Invalid IP address: {target}"
        ) from error

    if address.version != 4:
        raise WebEnumerationError(
            "Module 005 currently supports IPv4 only."
        )

    return str(address)


def detect_web_ports(
    services: list[dict[str, object]],
) -> list[tuple[int, str]]:
    """Find likely web services from stored port-scan data."""
    detected: set[tuple[int, str]] = set()

    for service in services:
        raw_port = service.get("port")
        service_name = str(
            service.get("service", "")
        ).lower()

        try:
            port = int(raw_port)
        except (TypeError, ValueError):
            continue

        if port in WEB_PORTS:
            detected.add((port, WEB_PORTS[port]))
            continue

        if "https" in service_name or "ssl/http" in service_name:
            detected.add((port, "https"))
        elif "http" in service_name:
            detected.add((port, "http"))

    return sorted(detected)


def build_url(
    target: str,
    port: int,
    scheme: str,
) -> str:
    """Construct a URL without unnecessary default-port notation."""
    if (
        scheme == "http"
        and port == 80
    ) or (
        scheme == "https"
        and port == 443
    ):
        return f"{scheme}://{target}/"

    return f"{scheme}://{target}:{port}/"


def decode_body(
    body: bytes,
    content_type: str,
) -> str:
    """Decode a small HTTP response body safely."""
    charset = "utf-8"

    for part in content_type.split(";"):
        part = part.strip()

        if part.lower().startswith("charset="):
            charset = part.split("=", 1)[1].strip()

    try:
        return body.decode(charset, errors="replace")
    except LookupError:
        return body.decode("utf-8", errors="replace")


def extract_title(
    body: bytes,
    content_type: str,
) -> str:
    """Extract an HTML page title."""
    if "html" not in content_type.lower():
        return ""

    parser = TitleParser()

    try:
        parser.feed(decode_body(body, content_type))
    except Exception:
        return ""

    return parser.title[:200]


def normalize_headers(
    headers: Any,
) -> dict[str, str]:
    """Convert response headers to a plain dictionary."""
    return {
        key.lower(): value
        for key, value in headers.items()
    }


def analyze_security_headers(
    headers: dict[str, str],
) -> tuple[list[str], list[str]]:
    """Identify present and absent common response headers."""
    present: list[str] = []
    missing: list[str] = []

    for normalized_name, display_name in SECURITY_HEADERS.items():
        if normalized_name in headers:
            present.append(display_name)
        else:
            missing.append(display_name)

    return sorted(present), sorted(missing)


def create_ssl_context() -> ssl.SSLContext:
    """
    Create a permissive context for authorized reconnaissance.

    This permits enumeration of appliances using self-signed
    certificates while still collecting certificate information.
    """
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def fetch_url(
    url: str,
    *,
    timeout: float = 8.0,
    max_bytes: int = 262_144,
) -> tuple[int, str, str, dict[str, str], bytes]:
    """Retrieve one URL with a limited response-body size."""
    from urllib.request import HTTPSHandler

    request = Request(
        url,
        headers={
            "User-Agent": "Cerberus/1.0 Authorized-Web-Enumerator",
            "Accept": (
                "text/html,application/xhtml+xml,"
                "text/plain,*/*;q=0.8"
            ),
            "Connection": "close",
        },
        method="GET",
    )

    opener = build_opener(
        HTTPSHandler(context=create_ssl_context()),
        LimitedRedirectHandler(),
    )

    try:
        with opener.open(
            request,
            timeout=timeout,
        ) as response:
            body = response.read(max_bytes)

            return (
                response.status,
                response.reason or "",
                response.geturl(),
                normalize_headers(response.headers),
                body,
            )

    except HTTPError as error:
        body = error.read(max_bytes)

        return (
            error.code,
            error.reason or "",
            error.geturl(),
            normalize_headers(error.headers),
            body,
        )

def fetch_robots(
    final_url: str,
) -> tuple[int | None, str]:
    """Retrieve a short preview of robots.txt."""
    robots_url = urljoin(final_url, "/robots.txt")

    try:
        status, _, _, headers, body = fetch_url(
            robots_url,
            timeout=5.0,
            max_bytes=16_384,
        )
    except (URLError, socket.timeout, TimeoutError, OSError):
        return None, ""

    content_type = headers.get("content-type", "text/plain")
    preview = decode_body(body, content_type)[:1000].strip()

    return status, preview


def format_certificate_name(
    name_parts: tuple[Any, ...],
) -> str:
    """Flatten an SSL certificate subject or issuer."""
    values: list[str] = []

    for group in name_parts:
        for key, value in group:
            values.append(f"{key}={value}")

    return ", ".join(values)


def collect_tls_certificate(
    target: str,
    port: int,
) -> TLSCertificate | None:
    """Collect basic TLS certificate and connection metadata."""
    context = create_ssl_context()

    try:
        with socket.create_connection(
            (target, port),
            timeout=6.0,
        ) as raw_socket:
            with context.wrap_socket(
                raw_socket,
                server_hostname=target,
            ) as tls_socket:
                certificate = tls_socket.getpeercert()
                cipher_info = tls_socket.cipher()

                return TLSCertificate(
                    subject=format_certificate_name(
                        certificate.get("subject", ())
                    ),
                    issuer=format_certificate_name(
                        certificate.get("issuer", ())
                    ),
                    serial_number=certificate.get(
                        "serialNumber",
                        "",
                    ),
                    not_before=certificate.get(
                        "notBefore",
                        "",
                    ),
                    not_after=certificate.get(
                        "notAfter",
                        "",
                    ),
                    protocol=tls_socket.version() or "",
                    cipher=(
                        cipher_info[0]
                        if cipher_info
                        else ""
                    ),
                )

    except (
        OSError,
        ssl.SSLError,
        socket.timeout,
        TimeoutError,
    ):
        return None


def enumerate_web_service(
    target: str,
    port: int,
    scheme: str,
) -> WebServiceResult:
    """Enumerate one HTTP or HTTPS service."""
    requested_url = build_url(target, port, scheme)

    try:
        (
            status_code,
            reason,
            final_url,
            headers,
            body,
        ) = fetch_url(requested_url)

        content_type = headers.get("content-type", "")
        present_headers, missing_headers = (
            analyze_security_headers(headers)
        )

        robots_status, robots_preview = fetch_robots(final_url)

        tls = (
            collect_tls_certificate(target, port)
            if scheme == "https"
            else None
        )

        return WebServiceResult(
            scheme=scheme,
            port=port,
            requested_url=requested_url,
            final_url=final_url,
            status_code=status_code,
            reason=reason,
            title=extract_title(body, content_type),
            server=headers.get("server", ""),
            content_type=content_type,
            content_length=headers.get("content-length", ""),
            headers=headers,
            present_security_headers=present_headers,
            missing_security_headers=missing_headers,
            robots_status=robots_status,
            robots_preview=robots_preview,
            tls=tls,
        )

    except (
        URLError,
        http.client.HTTPException,
        socket.timeout,
        TimeoutError,
        OSError,
    ) as error:
        return WebServiceResult(
            scheme=scheme,
            port=port,
            requested_url=requested_url,
            final_url="",
            status_code=0,
            reason="",
            title="",
            server="",
            content_type="",
            content_length="",
            headers={},
            present_security_headers=[],
            missing_security_headers=[],
            robots_status=None,
            robots_preview="",
            tls=None,
            error=str(error),
        )


def enumerate_host_web_services(
    target: str,
    services: list[dict[str, object]],
) -> WebEnumerationResult:
    """Enumerate all known web ports for one inventory host."""
    validated_target = validate_target(target)
    web_ports = detect_web_ports(services)

    if not web_ports:
        raise WebEnumerationError(
            "No known HTTP or HTTPS services exist for this host. "
            "Run the Port Scanner first."
        )

    results = [
        enumerate_web_service(
            validated_target,
            port,
            scheme,
        )
        for port, scheme in web_ports
    ]

    return WebEnumerationResult(
        timestamp=datetime.now().astimezone().isoformat(),
        target=validated_target,
        service_count=len(results),
        services=results,
    )


def save_web_enumeration(
    result: WebEnumerationResult,
) -> Path:
    """Save web-enumeration results as JSON."""
    WEB_SCAN_DIRECTORY.mkdir(
        parents=True,
        exist_ok=True,
    )

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    output_path = (
        WEB_SCAN_DIRECTORY
        / f"web_{result.target}_{timestamp}.json"
    )

    output_path.write_text(
        json.dumps(asdict(result), indent=2),
        encoding="utf-8",
    )

    return output_path
