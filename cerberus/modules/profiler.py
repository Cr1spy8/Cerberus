#!/usr/bin/env python3

from __future__ import annotations

import ipaddress
import json
import socket
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path

from cerberus.modules.inventory import InventoryHost


PROJECT_ROOT = Path(__file__).resolve().parents[2]
PROFILE_DIRECTORY = PROJECT_ROOT / "scans" / "profiles"


class ProfilerError(RuntimeError):
    """Raised when an asset cannot be profiled."""


@dataclass
class AssetProfile:
    timestamp: str
    ip_address: str
    hostname: str
    mac_address: str
    vendor: str
    device_type: str
    operating_system: str
    tags: list[str]
    evidence: list[str]


def validate_target(target: str) -> str:
    """Validate and normalize one IPv4 address."""
    try:
        address = ipaddress.ip_address(target)
    except ValueError as error:
        raise ProfilerError(f"Invalid IP address: {target}") from error

    if address.version != 4:
        raise ProfilerError("Module 004 currently supports IPv4 only.")

    return str(address)


def reverse_lookup(target: str) -> str:
    """Attempt to resolve an IP address to a hostname."""
    try:
        hostname, _, _ = socket.gethostbyaddr(target)
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return ""


def collect_layer2_identity(target: str) -> tuple[str, str]:
    """
    Ask Nmap for MAC/vendor data.

    MAC addresses are normally available only when the target is on the
    same Layer-2 network as Cerberus.
    """
    result = subprocess.run(
        [
            "nmap",
            "-sn",
            "-PR",
            "-n",
            "-oX",
            "-",
            target,
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        return "", ""

    try:
        root = ET.fromstring(result.stdout)
    except ET.ParseError:
        return "", ""

    mac_element = root.find("./host/address[@addrtype='mac']")

    if mac_element is None:
        return "", ""

    return (
        mac_element.attrib.get("addr", ""),
        mac_element.attrib.get("vendor", ""),
    )


def service_ports(host: InventoryHost) -> set[int]:
    """Return the known open TCP/UDP port numbers for one host."""
    ports: set[int] = set()

    for service in host.services:
        port = service.get("port")

        if isinstance(port, int):
            ports.add(port)
        elif isinstance(port, str) and port.isdigit():
            ports.add(int(port))

    return ports


def service_names(host: InventoryHost) -> set[str]:
    """Return normalized known service names."""
    names: set[str] = set()

    for service in host.services:
        name = service.get("service")

        if isinstance(name, str) and name:
            names.add(name.lower())

    return names


def infer_operating_system(
    host: InventoryHost,
) -> tuple[str, list[str]]:
    """Infer a broad OS family from known services."""
    ports = service_ports(host)
    names = service_names(host)
    evidence: list[str] = []

    windows_indicators = {
        135,
        139,
        445,
        3389,
        5985,
        5986,
    }

    linux_indicators = {
        22,
        111,
        2049,
    }

    if ports & windows_indicators:
        evidence.append(
            "Windows-associated ports observed: "
            + ", ".join(
                str(port)
                for port in sorted(ports & windows_indicators)
            )
        )
        return "windows", evidence

    if "microsoft-ds" in names or "ms-wbt-server" in names:
        evidence.append("Windows-associated service names observed.")
        return "windows", evidence

    if ports & linux_indicators:
        evidence.append(
            "Unix/Linux-associated ports observed: "
            + ", ".join(
                str(port)
                for port in sorted(ports & linux_indicators)
            )
        )
        return "linux_or_unix", evidence

    return "unknown", evidence


def infer_device_type(
    host: InventoryHost,
    vendor: str,
) -> tuple[str, list[str]]:
    """Infer a broad device role from services and vendor information."""
    ports = service_ports(host)
    names = service_names(host)
    evidence: list[str] = []
    vendor_lower = vendor.lower()

    if {
        "vmware",
        "virtualbox",
        "qemu",
    } & set(vendor_lower.split()):
        evidence.append(f"Virtualization vendor observed: {vendor}")
        return "virtual_machine_or_virtual_network", evidence

    if 53 in ports and (
        67 in ports
        or 68 in ports
        or 80 in ports
        or 443 in ports
    ):
        evidence.append(
            "DNS plus network-management services suggest a gateway."
        )
        return "router_or_gateway", evidence

    if 445 in ports or "microsoft-ds" in names:
        evidence.append("SMB service observed.")
        return "windows_host_or_server", evidence

    if 80 in ports or 443 in ports or 8080 in ports or 8443 in ports:
        evidence.append("Web service observed.")
        return "web_enabled_host", evidence

    if 22 in ports:
        evidence.append("SSH service observed.")
        return "linux_or_network_device", evidence

    return "unknown", evidence


def build_tags(
    host: InventoryHost,
    device_type: str,
    operating_system: str,
) -> list[str]:
    """Generate searchable asset tags."""
    tags: set[str] = set()

    if device_type != "unknown":
        tags.add(device_type)

    if operating_system != "unknown":
        tags.add(operating_system)

    for port in service_ports(host):
        tags.add(f"port:{port}")

    for service in service_names(host):
        tags.add(f"service:{service}")

    return sorted(tags)


def profile_host(host: InventoryHost) -> AssetProfile:
    """Create an asset profile using inventory and network evidence."""
    target = validate_target(host.ip_address)

    hostname = host.hostname or reverse_lookup(target)
    mac_address, vendor = collect_layer2_identity(target)

    operating_system, os_evidence = infer_operating_system(host)
    device_type, device_evidence = infer_device_type(
        host,
        vendor,
    )

    evidence = os_evidence + device_evidence

    if hostname:
        evidence.append(f"Reverse hostname resolved as {hostname}.")

    if mac_address:
        evidence.append(f"MAC address observed: {mac_address}.")

    if vendor:
        evidence.append(f"MAC vendor identified as {vendor}.")

    tags = build_tags(
        host,
        device_type,
        operating_system,
    )

    return AssetProfile(
        timestamp=datetime.now().astimezone().isoformat(),
        ip_address=target,
        hostname=hostname,
        mac_address=mac_address,
        vendor=vendor,
        device_type=device_type,
        operating_system=operating_system,
        tags=tags,
        evidence=evidence,
    )


def save_profile(profile: AssetProfile) -> Path:
    """Save an asset profile as JSON."""
    PROFILE_DIRECTORY.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = profile.ip_address.replace(":", "_")

    output_path = (
        PROFILE_DIRECTORY
        / f"profile_{safe_target}_{timestamp}.json"
    )

    output_path.write_text(
        json.dumps(asdict(profile), indent=2),
        encoding="utf-8",
    )

    return output_path
