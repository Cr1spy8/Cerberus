#!/usr/bin/env python3

from __future__ import annotations
from dataclasses import asdict, dataclass, field

import json
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path

from cerberus.modules.discovery import DiscoveryResult


PROJECT_ROOT = Path(__file__).resolve().parents[2]
INVENTORY_DIRECTORY = PROJECT_ROOT / "inventory"
INVENTORY_PATH = INVENTORY_DIRECTORY / "hosts.json"


class InventoryError(RuntimeError):
    """Raised when the Cerberus inventory cannot be processed."""

@dataclass
class InventoryHost:
    ip_address: str
    hostname: str
    status: str
    reason: str
    first_seen: str
    last_seen: str
    sightings: int
    services: list[dict[str, object]] = field(default_factory=list)
    last_scanned: str = ""
    mac_address: str = ""
    vendor: str = ""
    device_type: str = "unknown"
    operating_system: str = "unknown"
    tags: list[str] = field(default_factory=list)
    last_profiled: str = ""
    web_services: list[dict[str, object]] = field(default_factory=list)
    last_web_scan: str = ""


def load_inventory() -> dict[str, InventoryHost]:
    """Load the host inventory, indexed by IP address."""
    if not INVENTORY_PATH.exists():
        return {}

    try:
        raw_data = json.loads(
            INVENTORY_PATH.read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError) as error:
        raise InventoryError(
            f"Unable to read inventory: {error}"
        ) from error

    hosts: dict[str, InventoryHost] = {}

    for item in raw_data.get("hosts", []):
        item.setdefault("services", [])
        item.setdefault("last_scanned", "")
        item.setdefault("mac_address", "")
        item.setdefault("vendor", "")
        item.setdefault("device_type", "unknown")
        item.setdefault("operating_system", "unknown")
        item.setdefault("tags", [])
        item.setdefault("last_profiled", "")

        host = InventoryHost(**item)
        hosts[host.ip_address] = host

    return hosts


def update_inventory(
    discovery_result: DiscoveryResult,
) -> dict[str, InventoryHost]:
    """Merge a discovery result into the persistent inventory."""
    inventory = load_inventory()
    observed_at = discovery_result.timestamp
    currently_up = {
        host.ip_address for host in discovery_result.hosts
    }

    for existing_host in inventory.values():
        existing_host.status = (
            "up"
            if existing_host.ip_address in currently_up
            else "not_seen"
        )

    for discovered_host in discovery_result.hosts:
        existing_host = inventory.get(discovered_host.ip_address)

        if existing_host is None:
            inventory[discovered_host.ip_address] = InventoryHost(
                ip_address=discovered_host.ip_address,
                hostname=discovered_host.hostname,
                status="up",
                reason=discovered_host.reason,
                first_seen=observed_at,
                last_seen=observed_at,
                sightings=1,
            )
            continue

        existing_host.hostname = (
            discovered_host.hostname or existing_host.hostname
        )
        existing_host.status = "up"
        existing_host.reason = discovered_host.reason
        existing_host.last_seen = observed_at
        existing_host.sightings += 1

    return inventory


def save_inventory(
    inventory: dict[str, InventoryHost],
) -> Path:
    """Write the current host inventory to disk."""
    INVENTORY_DIRECTORY.mkdir(parents=True, exist_ok=True)

    payload = {
        "updated_at": datetime.now().astimezone().isoformat(),
        "host_count": len(inventory),
        "hosts": [
            asdict(host)
            for host in sorted(
                inventory.values(),
                key=lambda item: tuple(
                    int(part)
                    for part in item.ip_address.split(".")
                ),
            )
        ],
    }

    try:
        INVENTORY_PATH.write_text(
            json.dumps(payload, indent=2),
            encoding="utf-8",
        )
    except OSError as error:
        raise InventoryError(
            f"Unable to save inventory: {error}"
        ) from error

    return INVENTORY_PATH

def update_host_services(
    ip_address: str,
    services: list[dict[str, object]],
    scanned_at: str,
) -> Path:
    """Store port-scan intelligence for an inventory host."""
    inventory = load_inventory()
    host = inventory.get(ip_address)

    if host is None:
        raise InventoryError(
            f"{ip_address} does not exist in the Cerberus inventory."
        )

    host.services = services
    host.last_scanned = scanned_at

    return save_inventory(inventory)

def update_host_profile(
    ip_address: str,
    *,
    hostname: str,
    mac_address: str,
    vendor: str,
    device_type: str,
    operating_system: str,
    tags: list[str],
    profiled_at: str,
) -> Path:
    """Store profiling intelligence for an inventory host."""
    inventory = load_inventory()
    host = inventory.get(ip_address)

    if host is None:
        raise InventoryError(
            f"{ip_address} does not exist in the Cerberus inventory."
        )

    if hostname:
        host.hostname = hostname

    if mac_address:
        host.mac_address = mac_address

    if vendor:
        host.vendor = vendor

    host.device_type = device_type
    host.operating_system = operating_system
    host.tags = sorted(set(tags))
    host.last_profiled = profiled_at

    return save_inventory(inventory)
def update_host_web_services(
    ip_address: str,
    web_services: list[dict[str, object]],
    scanned_at: str,
) -> Path:
    """Store web-enumeration results for an inventory host."""
    inventory = load_inventory()
    host = inventory.get(ip_address)

    if host is None:
        raise InventoryError(
            f"{ip_address} does not exist in the Cerberus inventory."
        )

    host.web_services = web_services
    host.last_web_scan = scanned_at

    web_tags = {
        f"web:{service.get('scheme', 'http')}"
        for service in web_services
    }

    host.tags = sorted(set(host.tags) | web_tags)

    return save_inventory(inventory)
