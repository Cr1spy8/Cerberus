#!/usr/bin/env python3

from __future__ import annotations

import ipaddress
import json
import shutil
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCAN_DIRECTORY = PROJECT_ROOT / "scans" / "ports"


class ScannerError(RuntimeError):
    """Raised when a Cerberus port scan cannot be completed."""


@dataclass
class PortService:
    port: int
    protocol: str
    state: str
    service: str
    product: str
    version: str
    extra_info: str


@dataclass
class PortScanResult:
    timestamp: str
    target: str
    scan_profile: str
    open_port_count: int
    services: list[PortService]


def require_nmap() -> None:
    """Verify that Nmap is installed."""
    if shutil.which("nmap") is None:
        raise ScannerError(
            "Nmap was not found. Install it with: sudo apt install nmap"
        )


def validate_target(target: str) -> str:
    """Accept one IPv4 address and reject malformed input."""
    try:
        return str(ipaddress.ip_address(target))
    except ValueError as error:
        raise ScannerError(
            f"Invalid IP address: {target}"
        ) from error


def run_nmap_port_scan(target: str) -> str:
    """
    Run a quick TCP service scan.

    This scans Nmap's 100 most common TCP ports using a TCP connect
    scan and light service-version detection.
    """
    command = [
        "nmap",
        "-sT",
        "-sV",
        "--version-light",
        "--top-ports",
        "100",
        "-T4",
        "-n",
        "--reason",
        "-oX",
        "-",
        target,
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        raise ScannerError(
            result.stderr.strip() or "Nmap port scan failed."
        )

    return result.stdout


def parse_nmap_port_xml(xml_output: str) -> list[PortService]:
    """Extract open TCP services from Nmap XML."""
    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError as error:
        raise ScannerError(
            f"Unable to parse Nmap output: {error}"
        ) from error

    services: list[PortService] = []

    for port_element in root.findall("./host/ports/port"):
        state_element = port_element.find("state")

        if (
            state_element is None
            or state_element.attrib.get("state") != "open"
        ):
            continue

        service_element = port_element.find("service")
        service_attributes = (
            service_element.attrib
            if service_element is not None
            else {}
        )

        services.append(
            PortService(
                port=int(port_element.attrib["portid"]),
                protocol=port_element.attrib.get("protocol", "tcp"),
                state="open",
                service=service_attributes.get("name", "unknown"),
                product=service_attributes.get("product", ""),
                version=service_attributes.get("version", ""),
                extra_info=service_attributes.get("extrainfo", ""),
            )
        )

    return sorted(services, key=lambda item: item.port)


def scan_host(target: str) -> PortScanResult:
    """Run the complete Cerberus port-scanning workflow."""
    require_nmap()
    validated_target = validate_target(target)

    xml_output = run_nmap_port_scan(validated_target)
    services = parse_nmap_port_xml(xml_output)

    return PortScanResult(
        timestamp=datetime.now().astimezone().isoformat(),
        target=validated_target,
        scan_profile="quick_tcp_service_scan",
        open_port_count=len(services),
        services=services,
    )


def save_port_scan(result: PortScanResult) -> Path:
    """Save port-scan results as JSON."""
    SCAN_DIRECTORY.mkdir(parents=True, exist_ok=True)

    safe_target = result.target.replace(":", "_")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    output_path = (
        SCAN_DIRECTORY
        / f"portscan_{safe_target}_{timestamp}.json"
    )

    output_path.write_text(
        json.dumps(asdict(result), indent=2),
        encoding="utf-8",
    )

    return output_path
