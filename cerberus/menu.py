#!/usr/bin/env python3

from __future__ import annotations

import os
from collections.abc import Callable

from dataclasses import asdict

from cerberus.modules.scanner import (
    ScannerError,
    save_port_scan,
    scan_host,
)

from cerberus.modules.discovery import (
    DiscoveryError,
    discover_network,
    save_result,
)

from cerberus.modules.inventory import (
    InventoryError,
    load_inventory,
    save_inventory,
    update_host_profile,
    update_host_services,
    update_inventory,
)

from cerberus.modules.profiler import (
    ProfilerError,
    profile_host,
    save_profile,
)

def clear_screen() -> None:
    """Clear the terminal window."""
    os.system("clear")


def pause() -> None:
    """Wait for the operator before returning to the menu."""
    input("\nPress Enter to return to the main menu...")


def print_banner() -> None:
    print("=" * 62)
    print("                         CERBERUS")
    print("              Portable Penetration Testing Appliance")
    print("=" * 62)


def run_discovery_menu() -> None:
    """Run discovery and update the persistent inventory."""
    clear_screen()
    print_banner()
    print("\n[*] Starting network discovery...\n")

    try:
        result = discover_network()

        print(f"[+] Interface: {result.interface}")
        print(f"[+] Local IP:  {result.local_address}")
        print(f"[+] Network:   {result.network}")
        print(f"[+] Hosts:     {result.host_count}\n")

        if not result.hosts:
            print("[!] No live hosts were discovered.")
        else:
            print(
                f"{'IP Address':<18}"
                f"{'Status':<12}"
                f"{'Hostname':<24}"
                f"Reason"
            )
            print("-" * 70)

            for host in result.hosts:
                print(
                    f"{host.ip_address:<18}"
                    f"{host.status:<12}"
                    f"{host.hostname or '-':<24}"
                    f"{host.reason or '-'}"
                )

        scan_path = save_result(result)
        inventory = update_inventory(result)
        inventory_path = save_inventory(inventory)

        print(f"\n[+] Scan saved to:      {scan_path}")
        print(f"[+] Inventory updated: {inventory_path}")

    except (DiscoveryError, InventoryError) as error:
        print(f"[!] Discovery failed: {error}")

    pause()


def show_inventory_menu() -> None:
    """Display the persistent host inventory."""
    clear_screen()
    print_banner()
    print("\nCERBERUS HOST INVENTORY\n")

    try:
        inventory = load_inventory()
    except InventoryError as error:
        print(f"[!] Unable to load inventory: {error}")
        pause()
        return

    if not inventory:
        print("[!] Inventory is empty.")
        print("    Run Network Discovery first.")
        pause()
        return

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

    pause()

def run_port_scanner_menu() -> None:
    """Select an inventory host and run a quick TCP service scan."""
    clear_screen()
    print_banner()
    print("\nCERBERUS PORT SCANNER\n")

    try:
        inventory = load_inventory()
    except InventoryError as error:
        print(f"[!] Unable to load inventory: {error}")
        pause()
        return

    if not inventory:
        print("[!] Inventory is empty.")
        print("    Run Network Discovery first.")
        pause()
        return

    hosts = sorted(
        inventory.values(),
        key=lambda item: tuple(
            int(part) for part in item.ip_address.split(".")
        ),
    )

    for number, host in enumerate(hosts, start=1):
        hostname = host.hostname or "Unknown"
        print(
            f"[{number}] {host.ip_address:<18} "
            f"{hostname:<24} Status: {host.status}"
        )

    print("[0] Cancel")

    selection = input("\nSelect a target: ").strip()

    if selection == "0":
        return

    try:
        selected_number = int(selection)
        selected_host = hosts[selected_number - 1]
    except (ValueError, IndexError):
        print("\n[!] Invalid host selection.")
        pause()
        return

    print(
        f"\n[*] Scanning {selected_host.ip_address}..."
        "\n[*] Profile: top 100 TCP ports with light service detection\n"
    )

    try:
        result = scan_host(selected_host.ip_address)
        scan_path = save_port_scan(result)

        service_records = [
            asdict(service)
            for service in result.services
        ]

        inventory_path = update_host_services(
            ip_address=result.target,
            services=service_records,
            scanned_at=result.timestamp,
        )

    except (ScannerError, InventoryError) as error:
        print(f"[!] Port scan failed: {error}")
        pause()
        return

    if not result.services:
        print("[!] No open ports were found in this scan profile.")
    else:
        print(
            f"{'Port':<10}"
            f"{'Protocol':<12}"
            f"{'Service':<18}"
            f"Version"
        )
        print("-" * 72)

        for service in result.services:
            version_parts = [
                service.product,
                service.version,
                service.extra_info,
            ]

            version = " ".join(
                part for part in version_parts if part
            ) or "-"

            print(
                f"{service.port:<10}"
                f"{service.protocol:<12}"
                f"{service.service:<18}"
                f"{version}"
            )

    print(f"\n[+] Open ports:        {result.open_port_count}")
    print(f"[+] Scan saved to:     {scan_path}")
    print(f"[+] Inventory updated: {inventory_path}")

    pause()

def run_asset_profiler_menu() -> None:
    """Select an inventory host and build an asset profile."""
    clear_screen()
    print_banner()
    print("\nCERBERUS ASSET PROFILER\n")

    try:
        inventory = load_inventory()
    except InventoryError as error:
        print(f"[!] Unable to load inventory: {error}")
        pause()
        return

    if not inventory:
        print("[!] Inventory is empty.")
        print("    Run Network Discovery first.")
        pause()
        return

    hosts = sorted(
        inventory.values(),
        key=lambda item: tuple(
            int(part) for part in item.ip_address.split(".")
        ),
    )

    for number, host in enumerate(hosts, start=1):
        print(
            f"[{number}] {host.ip_address:<18} "
            f"{host.hostname or 'Unknown':<24} "
            f"Status: {host.status}"
        )

    print("[0] Cancel")

    selection = input("\nSelect an asset: ").strip()

    if selection == "0":
        return

    try:
        selected_number = int(selection)
        selected_host = hosts[selected_number - 1]
    except (ValueError, IndexError):
        print("\n[!] Invalid asset selection.")
        pause()
        return

    print(f"\n[*] Profiling {selected_host.ip_address}...\n")

    try:
        profile = profile_host(selected_host)
        profile_path = save_profile(profile)

        inventory_path = update_host_profile(
            ip_address=profile.ip_address,
            hostname=profile.hostname,
            mac_address=profile.mac_address,
            vendor=profile.vendor,
            device_type=profile.device_type,
            operating_system=profile.operating_system,
            tags=profile.tags,
            profiled_at=profile.timestamp,
        )

    except (ProfilerError, InventoryError) as error:
        print(f"[!] Asset profiling failed: {error}")
        pause()
        return

    print(f"{'IP Address:':<20}{profile.ip_address}")
    print(f"{'Hostname:':<20}{profile.hostname or 'Unknown'}")
    print(f"{'MAC Address:':<20}{profile.mac_address or 'Unavailable'}")
    print(f"{'Vendor:':<20}{profile.vendor or 'Unknown'}")
    print(f"{'Device Type:':<20}{profile.device_type}")
    print(f"{'Operating System:':<20}{profile.operating_system}")

    print("\nTags:")

    if profile.tags:
        for tag in profile.tags:
            print(f"  - {tag}")
    else:
        print("  - None")

    print("\nEvidence:")

    if profile.evidence:
        for evidence_item in profile.evidence:
            print(f"  - {evidence_item}")
    else:
        print("  - No identifying evidence collected.")

    print(f"\n[+] Profile saved to:   {profile_path}")
    print(f"[+] Inventory updated: {inventory_path}")

    pause()

def show_planned_feature(feature_name: str) -> None:
    """Display a placeholder for a planned Cerberus module."""
    clear_screen()
    print_banner()
    print(f"\n{feature_name}\n")
    print("[*] This module is planned but has not been implemented yet.")
    pause()


def exit_cerberus() -> None:
    clear_screen()
    print_banner()
    print("\nCerberus shutting down.\n")


def build_menu_actions() -> dict[str, Callable[[], None]]:
    """Map menu selections to Cerberus functions."""
    return {
        "1": run_discovery_menu,
        "2": show_inventory_menu,
        "3": run_port_scanner_menu,
        "4": run_asset_profiler_menu,
        "5": lambda: show_planned_feature("WEB ENUMERATION"),
        "6": lambda: show_planned_feature("SMB ENUMERATION"),
        "7": lambda: show_planned_feature("REPORTS"),
        "8": lambda: show_planned_feature("SETTINGS"),
    }


def run_menu() -> None:
    """Launch the interactive Cerberus appliance interface."""
    actions = build_menu_actions()

    while True:
        clear_screen()
        print_banner()

        print(
            """
[1] Discover Network
[2] View Host Inventory
[3] Port Scanner
[4] Asset Profiler
[5] Web Enumeration          [Planned]
[6] SMB Enumeration          [Planned]
[7] Reports                  [Planned]
[8] Settings                 [Planned]
[0] Exit
"""
        )

        selection = input("cerberus > ").strip()

        if selection == "0":
            exit_cerberus()
            return

        action = actions.get(selection)

        if action is None:
            print("\n[!] Invalid selection.")
            pause()
            continue

        action()
