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
    update_host_web_services,
    update_inventory,
)
from cerberus.modules.profiler import (
    ProfilerError,
    profile_host,
    save_profile,
)
from cerberus.modules.web_enum import (
    WebEnumerationError,
    enumerate_host_web_services,
    save_web_enumeration,
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

def run_web_enumeration_menu() -> None:
    """Select an inventory host and enumerate known web services."""
    clear_screen()
    print_banner()
    print("\nCERBERUS WEB ENUMERATION\n")

    try:
        inventory = load_inventory()
    except InventoryError as error:
        print(f"[!] Unable to load inventory: {error}")
        pause()
        return

    eligible_hosts = [
        host
        for host in inventory.values()
        if any(
            "http" in str(service.get("service", "")).lower()
            or int(service.get("port", 0)) in {
                80,
                443,
                8000,
                8080,
                8443,
            }
            for service in host.services
        )
    ]

    eligible_hosts.sort(
        key=lambda item: tuple(
            int(part)
            for part in item.ip_address.split(".")
        )
    )

    if not eligible_hosts:
        print("[!] No inventoried hosts have known web services.")
        print("    Run the Port Scanner against a web-enabled target first.")
        pause()
        return

    for number, host in enumerate(
        eligible_hosts,
        start=1,
    ):
        web_ports = [
            str(service.get("port"))
            for service in host.services
            if (
                "http"
                in str(service.get("service", "")).lower()
                or int(service.get("port", 0))
                in {80, 443, 8000, 8080, 8443}
            )
        ]

        print(
            f"[{number}] {host.ip_address:<18} "
            f"Ports: {', '.join(web_ports)}"
        )

    print("[0] Cancel")
    selection = input("\nSelect a web target: ").strip()

    if selection == "0":
        return

    try:
        selected_host = eligible_hosts[int(selection) - 1]
    except (ValueError, IndexError):
        print("\n[!] Invalid target selection.")
        pause()
        return

    print(
        f"\n[*] Enumerating web services on "
        f"{selected_host.ip_address}...\n"
    )

    try:
        result = enumerate_host_web_services(
            selected_host.ip_address,
            selected_host.services,
        )

        scan_path = save_web_enumeration(result)

        web_records = [
            asdict(service)
            for service in result.services
        ]

        inventory_path = update_host_web_services(
            ip_address=result.target,
            web_services=web_records,
            scanned_at=result.timestamp,
        )

    except (
        WebEnumerationError,
        InventoryError,
    ) as error:
        print(f"[!] Web enumeration failed: {error}")
        pause()
        return

    for service in result.services:
        print("-" * 70)
        print(f"URL:          {service.requested_url}")

        if service.error:
            print(f"Error:        {service.error}")
            continue

        print(f"Final URL:    {service.final_url}")
        print(
            f"Status:       "
            f"{service.status_code} {service.reason}"
        )
        print(f"Title:        {service.title or 'Unknown'}")
        print(f"Server:       {service.server or 'Not disclosed'}")
        print(
            f"Content-Type: "
            f"{service.content_type or 'Unknown'}"
        )

        if service.present_security_headers:
            print(
                "Present Headers: "
                + ", ".join(
                    service.present_security_headers
                )
            )

        if service.missing_security_headers:
            print(
                "Missing Headers: "
                + ", ".join(
                    service.missing_security_headers
                )
            )

        if service.robots_status is not None:
            print(
                f"robots.txt:   HTTP "
                f"{service.robots_status}"
            )

        if service.tls is not None:
            print(
                f"TLS:          "
                f"{service.tls.protocol or 'Unknown'}"
            )
            print(
                f"Certificate:  "
                f"{service.tls.subject or 'Unavailable'}"
            )

    print(f"\n[+] Web services:      {result.service_count}")
    print(f"[+] Results saved to:  {scan_path}")
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
        "5": run_web_enumeration_menu,
        "6": lambda: show_planned_feature("SMB ENUMERATION"),
        "7": lambda: show_planned_feature("DNS INTELLIGENCE"),
	"8": lambda: show_planned_feature("REPORTS"),
        "9": lambda: show_planned_feature("SPLUNK INTEGRATION"),
	"10": lambda: show_planned_feature("HONEYPOT"),
	"11": lambda: show_planned_feature("SETTINGS"),
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
[5] Web Enumeration
[6] SMB Enumeration          [Planned]
[7] DNS Intelligence         [Planned]
[8] Reports                  [Planned]
[9] Splunk Integration       [Planned]
[10] Honeypot		     [Planned]
[11] Settings                [Planned]
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
