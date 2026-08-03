#!/usr/bin/env python3

from __future__ import annotations

import ipaddress
import json
import shutil
import subprocess
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCAN_DIRECTORY = PROJECT_ROOT / "scans"


class DiscoveryError(RuntimeError):
    """Raised when network discovery cannot be completed."""


@dataclass
class DiscoveredHost:
    ip_address: str
    hostname: str = ""
    status: str = "up"
    reason: str = ""


@dataclass
class DiscoveryResult:
    timestamp: str
    interface: str
    local_address: str
    network: str
    host_count: int
    hosts: list[DiscoveredHost]


def require_nmap() -> None:
    """Verify that Nmap is installed."""
    if shutil.which("nmap") is None:
        raise DiscoveryError(
            "Nmap was not found. Install it with: sudo apt install nmap"
        )


def get_default_interface() -> str:
    """Return the interface used by the default IPv4 route."""
    result = subprocess.run(
        ["ip", "-4", "route", "show", "default"],
        capture_output=True,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        raise DiscoveryError(result.stderr.strip() or "Unable to read routes.")

    fields = result.stdout.split()

    if "dev" not in fields:
        raise DiscoveryError("No default IPv4 interface was found.")

    return fields[fields.index("dev") + 1]


def get_interface_address(interface: str) -> str:
    """Return an interface's IPv4 address in CIDR notation."""
    result = subprocess.run(
        ["ip", "-4", "-o", "addr", "show", "dev", interface],
        capture_output=True,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        raise DiscoveryError(
            result.stderr.strip() or f"Unable to inspect {interface}."
        )

    for line in result.stdout.splitlines():
        fields = line.split()

        if "inet" in fields:
            return fields[fields.index("inet") + 1]

    raise DiscoveryError(f"No IPv4 address was found on {interface}.")


def run_nmap_discovery(network: str) -> str:
    """Perform an Nmap ping sweep and return XML output."""
    result = subprocess.run(
        [
            "nmap",
            "-sn",
            "-n",
            "--reason",
            "-oX",
            "-",
            network,
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        raise DiscoveryError(
            result.stderr.strip() or "Nmap discovery scan failed."
        )

    return result.stdout


def parse_nmap_xml(xml_output: str) -> list[DiscoveredHost]:
    """Parse live hosts from Nmap XML output."""
    import xml.etree.ElementTree as ET

    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError as error:
        raise DiscoveryError(f"Unable to parse Nmap output: {error}") from error

    hosts: list[DiscoveredHost] = []

    for host_element in root.findall("host"):
        status_element = host_element.find("status")

        if (
            status_element is None
            or status_element.attrib.get("state") != "up"
        ):
            continue

        address_element = host_element.find(
            "address[@addrtype='ipv4']"
        )

        if address_element is None:
            continue

        hostname = ""
        hostname_element = host_element.find("hostnames/hostname")

        if hostname_element is not None:
            hostname = hostname_element.attrib.get("name", "")

        hosts.append(
            DiscoveredHost(
                ip_address=address_element.attrib["addr"],
                hostname=hostname,
                status="up",
                reason=status_element.attrib.get("reason", ""),
            )
        )

    return hosts


def discover_network() -> DiscoveryResult:
    """Run the complete discovery workflow."""
    require_nmap()

    interface = get_default_interface()
    local_address = get_interface_address(interface)
    network = str(ipaddress.ip_interface(local_address).network)

    xml_output = run_nmap_discovery(network)
    hosts = parse_nmap_xml(xml_output)

    return DiscoveryResult(
        timestamp=datetime.now().astimezone().isoformat(),
        interface=interface,
        local_address=local_address,
        network=network,
        host_count=len(hosts),
        hosts=hosts,
    )


def save_result(result: DiscoveryResult) -> Path:
    """Save discovery results as structured JSON."""
    SCAN_DIRECTORY.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = SCAN_DIRECTORY / f"discovery_{timestamp}.json"

    output_path.write_text(
        json.dumps(asdict(result), indent=2),
        encoding="utf-8",
    )

    return output_path
