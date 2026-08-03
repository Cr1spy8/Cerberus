#!/usr/bin/env python3

from __future__ import annotations
from cerberus.menu import run_menu
import argparse
import sys

from cerberus.modules.discovery import (
    DiscoveryError,
    discover_network,
    save_result,
)

from cerberus.modules.inventory import (
    InventoryError,
    load_inventory,
    save_inventory,
    update_inventory,
)


def run_discovery() -> int:
    print("=" * 46)
    print("          CERBERUS NETWORK DISCOVERY")
    print("=" * 46)

    try:
        result = discover_network()
    except DiscoveryError as error:
        print(f"[!] Discovery failed: {error}")
        return 1

    print(f"[+] Interface: {result.interface}")
    print(f"[+] Local IP:  {result.local_address}")
    print(f"[+] Network:   {result.network}")
    print(f"[+] Hosts:     {result.host_count}\n")

    if not result.hosts:
        print("[!] No live hosts were discovered.")
    else:
        for host in result.hosts:
            hostname = f" ({host.hostname})" if host.hostname else ""
            reason = f" [{host.reason}]" if host.reason else ""

            print(
                f"    {host.ip_address}{hostname}{reason}"
            )

    output_path = save_result(result)

    try:
        inventory = update_inventory(result)
        inventory_path = save_inventory(inventory)
    except InventoryError as error:
        print(f"\n[!] Inventory update failed: {error}")
        return 1

    print(f"\n[+] Scan saved to:      {output_path}")
    print(f"[+] Inventory updated: {inventory_path}")

    return 0


def show_inventory() -> int:
    try:
        inventory = load_inventory()
    except InventoryError as error:
        print(f"[!] Unable to load inventory: {error}")
        return 1

    print("=" * 78)
    print("                         CERBERUS HOST INVENTORY")
    print("=" * 78)

    if not inventory:
        print("[!] Inventory is empty. Run: cerberus discover")
        return 0

    print(
        f"{'IP Address':<18}"
        f"{'Status':<12}"
        f"{'Seen':<8}"
        f"{'Hostname':<24}"
        f"Reason"
    )
    print("-" * 78)

    for host in sorted(
        inventory.values(),
        key=lambda item: tuple(
            int(part) for part in item.ip_address.split(".")
        ),
    ):
        print(
            f"{host.ip_address:<18}"
            f"{host.status:<12}"
            f"{host.sightings:<8}"
            f"{host.hostname or '-':<24}"
            f"{host.reason or '-'}"
        )

    return 0

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cerberus",
        description="Cerberus portable penetration-testing appliance",
    )

    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser(
        "discover",
        help="Discover live hosts on the active IPv4 network",
    )
    subparsers.add_parser(
        "inventory",
        help="Display the persistent Cerberus host inventory",
    )
    subparsers.add_parser(
        "menu",
        help="Launch the interactive Cerberus appliance interface",
    )

    return parser


def main() -> int:
    parser = build_parser()
    arguments = parser.parse_args()

    if arguments.command == "discover":
        return run_discovery()

    if arguments.command == "inventory":
        return show_inventory()

    if arguments.command == "menu" or arguments.command is None:
        run_menu()
        return 0

    parser.print_help()
    return 0

if __name__ == "__main__":
    sys.exit(main())
