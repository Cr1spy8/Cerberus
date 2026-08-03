#!/usr/bin/env python3

from __future__ import annotations

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
