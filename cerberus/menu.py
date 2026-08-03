#!/usr/bin/env python3

from __future__ import annotations

import os
from collections.abc import Callable

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
        "3": lambda: show_planned_feature("PORT SCANNER"),
        "4": lambda: show_planned_feature("WEB ENUMERATION"),
        "5": lambda: show_planned_feature("SMB ENUMERATION"),
        "6": lambda: show_planned_feature("REPORTS"),
        "7": lambda: show_planned_feature("SETTINGS"),
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
[3] Port Scanner             [Planned]
[4] Web Enumeration          [Planned]
[5] SMB Enumeration          [Planned]
[6] Reports                  [Planned]
[7] Settings                 [Planned]
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
