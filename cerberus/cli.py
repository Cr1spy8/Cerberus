#!/usr/bin/env python3

from __future__ import annotations

import argparse
import sys

from cerberus.modules.discovery import (
    DiscoveryError,
    discover_network,
    save_result,
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
    print(f"\n[+] Results saved to: {output_path}")

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

    return parser


def main() -> int:
    parser = build_parser()
    arguments = parser.parse_args()

    if arguments.command == "discover":
        return run_discovery()

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
