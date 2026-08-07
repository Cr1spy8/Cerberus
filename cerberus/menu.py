#!/usr/bin/env python3

from __future__ import annotations
import os
from collections.abc import Callable
from dataclasses import asdict
from cerberus.branding import terminal_banner

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
    update_host_intelligence,
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
from cerberus.modules.device_intel import (
    DeviceIntelligenceError,
    analyze_device,
    save_device_intelligence,
)
from cerberus.modules.reporting import (
    ReportingError,
    build_host_report,
    build_network_report,
    list_existing_reports,
    save_all_formats,
)
from cerberus.modules.splunk_integration import (
    SplunkIntegrationError,
    export_all,
    export_assessment_summary,
    export_device_intelligence,
    export_inventory,
    export_security_findings,
    load_export_history,
    load_splunk_config,
    test_connection,
)
from cerberus.modules.honeypot import (
    HoneypotError,
    export_new_events_to_splunk,
    honeypot_statistics,
    honeypot_status,
    load_honeypot_events,
    start_honeypot,
    stop_honeypot,
)
from cerberus.modules.settings import (
    CONFIG_FILE,
    configure_honeypot,
    configure_network,
    configure_reporting,
    configure_splunk,
    deployment_ready,
    reset_config,
    system_checks,
    view_configuration,
)

def clear_screen() -> None:
    """Clear the terminal window."""
    os.system("clear")

def pause() -> None:
    """Wait for the operator before returning to the menu."""
    input("\nPress Enter to return to the main menu...")

def print_banner() -> None:
    """Display the Cerberus application banner."""
    print(terminal_banner())



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

def run_device_intelligence_menu() -> None:
    """Analyze an inventory host using collected Cerberus evidence."""
    clear_screen()
    print_banner()
    print("\nCERBERUS DEVICE INTELLIGENCE\n")

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
            int(part)
            for part in item.ip_address.split(".")
        ),
    )

    for number, host in enumerate(hosts, start=1):
        print(
            f"[{number}] {host.ip_address:<18} "
            f"{host.hostname or 'Unknown':<24} "
            f"Services: {len(host.services)}"
        )

    print("[0] Cancel")

    selection = input("\nSelect an asset: ").strip()

    if selection == "0":
        return

    try:
        selected_host = hosts[int(selection) - 1]
    except (ValueError, IndexError):
        print("\n[!] Invalid asset selection.")
        pause()
        return

    print(
        f"\n[*] Analyzing {selected_host.ip_address}...\n"
    )

    try:
        result = analyze_device(selected_host)
        result_path = save_device_intelligence(result)

        intelligence_record = asdict(result)

        inventory_path = update_host_intelligence(
            ip_address=result.ip_address,
            intelligence=intelligence_record,
            analyzed_at=result.timestamp,
        )

    except (
        DeviceIntelligenceError,
        InventoryError,
    ) as error:
        print(f"[!] Device Intelligence failed: {error}")
        pause()
        return

    print(f"{'IP Address:':<22}{result.ip_address}")
    print(f"{'Classification:':<22}{result.classification}")
    print(f"{'Operating System:':<22}{result.operating_system}")
    print(f"{'Vendor:':<22}{result.vendor or 'Unknown'}")
    print(
        f"{'Confidence:':<22}"
        f"{result.confidence_score}%"
    )
    print(
        f"{'Risk:':<22}"
        f"{result.risk_level.upper()} "
        f"({result.risk_score}/100)"
    )

    print("\nEvidence:")

    if result.evidence:
        for evidence in result.evidence:
            print(f"  - {evidence}")
    else:
        print("  - Insufficient evidence collected.")

    print("\nFindings:")

    if result.findings:
        for finding in result.findings:
            print(
                f"  [{finding.severity.upper()}] "
                f"{finding.title}"
            )
            print(f"      {finding.evidence}")
    else:
        print("  - No specific findings generated.")

    print("\nRecommendations:")

    if result.recommendations:
        for recommendation in result.recommendations:
            print(f"  - {recommendation}")
    else:
        print("  - No recommendations generated.")

    print(f"\n[+] Results saved to:  {result_path}")
    print(f"[+] Inventory updated: {inventory_path}")

    pause()

def generate_network_report_menu() -> None:
    """Generate full-network reports in all supported formats."""
    clear_screen()
    print_banner()
    print("\nCERBERUS FULL NETWORK REPORT\n")

    network_name = input(
        "Assessment name "
        "[Cerberus Assessment Network]: "
    ).strip()

    if not network_name:
        network_name = "Cerberus Assessment Network"

    print("\n[*] Building full-network assessment report...\n")

    try:
        report = build_network_report(network_name)
        paths = save_all_formats(report)
    except ReportingError as error:
        print(f"[!] Report generation failed: {error}")
        pause()
        return

    print(f"[+] Hosts included: {report.summary.total_hosts}")
    print(
        f"[+] Open services: "
        f"{report.summary.total_open_services}"
    )

    print("\nGenerated reports:")

    for format_name, path in paths.items():
        print(f"  - {format_name.upper():<10}{path}")

    pause()

def generate_host_report_menu() -> None:
    """Generate reports for one inventory host."""
    clear_screen()
    print_banner()
    print("\nCERBERUS SINGLE HOST REPORT\n")

    try:
        inventory = load_inventory()
    except InventoryError as error:
        print(f"[!] Unable to load inventory: {error}")
        pause()
        return

    if not inventory:
        print("[!] Inventory is empty.")
        pause()
        return

    hosts = sorted(
        inventory.values(),
        key=lambda item: tuple(
            int(part)
            for part in item.ip_address.split(".")
        ),
    )

    for number, host in enumerate(hosts, start=1):
        risk_level = str(
            host.intelligence.get(
                "risk_level",
                "informational",
            )
        )

        print(
            f"[{number}] {host.ip_address:<18} "
            f"Risk: {risk_level}"
        )

    print("[0] Cancel")

    selection = input("\nSelect an asset: ").strip()

    if selection == "0":
        return

    try:
        host = hosts[int(selection) - 1]
    except (ValueError, IndexError):
        print("\n[!] Invalid asset selection.")
        pause()
        return

    network_name = input(
        "\nAssessment name "
        "[Cerberus Assessment Network]: "
    ).strip()

    if not network_name:
        network_name = "Cerberus Assessment Network"

    print(f"\n[*] Building report for {host.ip_address}...\n")

    try:
        report = build_host_report(
            host.ip_address,
            network_name,
        )
        paths = save_all_formats(report)
    except ReportingError as error:
        print(f"[!] Report generation failed: {error}")
        pause()
        return

    print("Generated reports:")

    for format_name, path in paths.items():
        print(f"  - {format_name.upper():<10}{path}")

    pause()


def view_existing_reports_menu() -> None:
    """Display generated report files."""
    clear_screen()
    print_banner()
    print("\nCERBERUS EXISTING REPORTS\n")

    reports = list_existing_reports()

    if not reports:
        print("[!] No reports have been generated yet.")
        pause()
        return

    for number, report_path in enumerate(
        reports[:30],
        start=1,
    ):
        size_kb = report_path.stat().st_size / 1024

        print(
            f"[{number:>2}] "
            f"{report_path.name:<58} "
            f"{size_kb:>8.1f} KB"
        )

    print(
        "\n[*] Reports are stored in: "
        f"{reports[0].parent}"
    )

    pause()


def run_reporting_menu() -> None:
    """Launch the Cerberus reporting submenu."""
    while True:
        clear_screen()
        print_banner()

        print(
            """
CERBERUS REPORTING ENGINE

[1] Generate Full Network Report
[2] Generate Single Host Report
[3] View Existing Reports
[0] Return to Main Menu
"""
        )

        selection = input("reports > ").strip()

        if selection == "0":
            return

        if selection == "1":
            generate_network_report_menu()
            continue

        if selection == "2":
            generate_host_report_menu()
            continue

        if selection == "3":
            view_existing_reports_menu()
            continue

        print("\n[!] Invalid selection.")
        pause()

def display_splunk_export_result(
    export_name: str,
    count: int,
    errors: list[str],
) -> None:
    """Display the result of one Splunk export operation."""
    print(f"\n{export_name}")
    print("-" * 50)
    print(f"[+] Events exported: {count}")

    if errors:
        print(f"[!] Errors: {len(errors)}")

        for error in errors:
            print(f"    - {error}")
    else:
        print("[+] Export completed without errors.")

def test_splunk_connection_menu() -> None:
    """Test the configured Splunk HEC connection."""
    clear_screen()
    print_banner()
    print("\nCERBERUS SPLUNK CONNECTION TEST\n")

    try:
        config = load_splunk_config()

        print(f"HEC URL:    {config.hec_url}")
        print(f"Index:      {config.index}")
        print(f"Source:     {config.source}")
        print("\n[*] Sending integration-test event...\n")

        response = test_connection(config)

    except SplunkIntegrationError as error:
        print(f"[!] Splunk connection failed: {error}")
        pause()
        return

    if response.success:
        print("[+] Splunk HEC connection successful.")
    else:
        print("[!] Splunk responded, but rejected the event.")

    print(f"[+] HTTP status: {response.status_code}")
    print(f"[+] Response:    {response.message}")

    pause()

def export_inventory_menu() -> None:
    """Export the current Cerberus inventory to Splunk."""
    clear_screen()
    print_banner()
    print("\nCERBERUS SPLUNK — HOST INVENTORY\n")

    try:
        config = load_splunk_config()
        count, errors = export_inventory(config)
    except SplunkIntegrationError as error:
        print(f"[!] Inventory export failed: {error}")
        pause()
        return

    display_splunk_export_result(
        "Host Inventory Export",
        count,
        errors,
    )

    pause()

def export_device_intelligence_menu() -> None:
    """Export Device Intelligence records to Splunk."""
    clear_screen()
    print_banner()
    print("\nCERBERUS SPLUNK — DEVICE INTELLIGENCE\n")

    try:
        config = load_splunk_config()
        count, errors = export_device_intelligence(config)
    except SplunkIntegrationError as error:
        print(f"[!] Device Intelligence export failed: {error}")
        pause()
        return

    display_splunk_export_result(
        "Device Intelligence Export",
        count,
        errors,
    )

    pause()


def export_security_findings_menu() -> None:
    """Export individual Cerberus findings to Splunk."""
    clear_screen()
    print_banner()
    print("\nCERBERUS SPLUNK — SECURITY FINDINGS\n")

    try:
        config = load_splunk_config()
        count, errors = export_security_findings(config)
    except SplunkIntegrationError as error:
        print(f"[!] Security Findings export failed: {error}")
        pause()
        return

    display_splunk_export_result(
        "Security Findings Export",
        count,
        errors,
    )

    pause()


def export_assessment_summary_menu() -> None:
    """Export the current network assessment summary."""
    clear_screen()
    print_banner()
    print("\nCERBERUS SPLUNK — ASSESSMENT SUMMARY\n")

    try:
        config = load_splunk_config()
        count, errors = export_assessment_summary(config)
    except SplunkIntegrationError as error:
        print(f"[!] Assessment export failed: {error}")
        pause()
        return

    display_splunk_export_result(
        "Assessment Summary Export",
        count,
        errors,
    )

    pause()

def export_all_splunk_data_menu() -> None:
    """Export every currently supported Cerberus dataset."""
    clear_screen()
    print_banner()
    print("\nCERBERUS SPLUNK — FULL EXPORT\n")

    print(
        "This operation exports:\n"
        "  - Host Inventory\n"
        "  - Device Intelligence\n"
        "  - Security Findings\n"
        "  - Assessment Summary\n"
    )

    confirmation = input(
        "Continue with full export? [y/N]: "
    ).strip().lower()

    if confirmation not in {"y", "yes"}:
        print("\n[*] Full export cancelled.")
        pause()
        return

    try:
        config = load_splunk_config()
        results = export_all(config)
    except SplunkIntegrationError as error:
        print(f"[!] Full Splunk export failed: {error}")
        pause()
        return

    total_exported = 0
    total_errors = 0

    for export_name, result in results.items():
        count, errors = result
        total_exported += count
        total_errors += len(errors)

        display_splunk_export_result(
            export_name.replace("_", " ").title(),
            count,
            errors,
        )

    print("\n" + "=" * 50)
    print(f"[+] Total events exported: {total_exported}")
    print(f"[+] Total errors:          {total_errors}")

    pause()

def view_splunk_export_history_menu() -> None:
    """Display the local Splunk export-history log."""
    clear_screen()
    print_banner()
    print("\nCERBERUS SPLUNK EXPORT HISTORY\n")

    history = load_export_history()

    if not history:
        print("[!] No Splunk export history exists.")
        pause()
        return

    print(
        f"{'Timestamp':<34}"
        f"{'Export Type':<24}"
        f"{'Status':<18}"
        f"{'Events':<8}"
    )
    print("-" * 84)

    for entry in reversed(history[-30:]):
        print(
            f"{str(entry.get('timestamp', '')):<34}"
            f"{str(entry.get('export_type', '')):<24}"
            f"{str(entry.get('status', '')):<18}"
            f"{str(entry.get('event_count', 0)):<8}"
        )

        message = str(entry.get("message", "")).strip()

        if message:
            print(f"    {message}")

    pause()

def run_splunk_integration_menu() -> None:
    """Launch the Cerberus Splunk Integration submenu."""
    while True:
        clear_screen()
        print_banner()

        print(
            """
CERBERUS SPLUNK INTEGRATION

[1] Test Splunk Connection
[2] Export Host Inventory
[3] Export Device Intelligence
[4] Export Security Findings
[5] Export Assessment Summary
[6] Export All Cerberus Data
[7] View Export History
[0] Return to Main Menu
"""
        )

        selection = input("splunk > ").strip()

        if selection == "0":
            return

        actions = {
            "1": test_splunk_connection_menu,
            "2": export_inventory_menu,
            "3": export_device_intelligence_menu,
            "4": export_security_findings_menu,
            "5": export_assessment_summary_menu,
            "6": export_all_splunk_data_menu,
            "7": view_splunk_export_history_menu,
        }

        action = actions.get(selection)

        if action is None:
            print("\n[!] Invalid selection.")
            pause()
            continue

        action()

def start_honeypot_menu() -> None:
    """Start the Cerberus HTTP honeypot."""
    clear_screen()
    print_banner()
    print("\nCERBERUS HONEYPOT — START\n")

    try:
        status = start_honeypot()
    except HoneypotError as error:
        print(f"[!] Unable to start honeypot: {error}")
        pause()
        return

    print("[+] Honeypot started successfully.")
    print(f"[+] PID:      {status['pid']}")
    print(f"[+] Port:     {status['port']}")
    print(
        f"[+] URL:      "
        f"http://<Cerberus-IP>:{status['port']}/"
    )
    print(f"[+] Log file: {status['event_log']}")

    pause()


def stop_honeypot_menu() -> None:
    """Stop the running Cerberus honeypot."""
    clear_screen()
    print_banner()
    print("\nCERBERUS HONEYPOT — STOP\n")

    confirmation = input(
        "Stop the running honeypot? [y/N]: "
    ).strip().lower()

    if confirmation not in {"y", "yes"}:
        print("\n[*] Stop cancelled.")
        pause()
        return

    try:
        stop_honeypot()
    except HoneypotError as error:
        print(f"[!] Unable to stop honeypot: {error}")
        pause()
        return

    print("\n[+] Honeypot stopped.")

    pause()


def view_honeypot_status_menu() -> None:
    """Display honeypot service state."""
    clear_screen()
    print_banner()
    print("\nCERBERUS HONEYPOT STATUS\n")

    status = honeypot_status()

    print(
        f"Status:       "
        f"{'RUNNING' if status['running'] else 'STOPPED'}"
    )
    print(f"PID:          {status['pid'] or '-'}")
    print(f"Listen Host:  {status['host']}")
    print(f"Listen Port:  {status['port']}")
    print(f"Event Log:    {status['event_log']}")
    print(f"Service Log:  {status['service_log']}")

    pause()


def view_recent_honeypot_events_menu() -> None:
    """Display recently captured honeypot interactions."""
    clear_screen()
    print_banner()
    print("\nCERBERUS RECENT HONEYPOT EVENTS\n")

    try:
        events = load_honeypot_events(limit=20)
    except HoneypotError as error:
        print(f"[!] Unable to read events: {error}")
        pause()
        return

    if not events:
        print("[!] No honeypot interactions recorded.")
        pause()
        return

    print(
        f"{'Timestamp':<34}"
        f"{'Source IP':<18}"
        f"{'Method':<9}"
        f"{'Path'}"
    )
    print("-" * 90)

    for event in reversed(events):
        print(
            f"{str(event.get('timestamp', '')):<34}"
            f"{str(event.get('source_ip', '')):<18}"
            f"{str(event.get('http_method', '')):<9}"
            f"{str(event.get('request_path', ''))}"
        )

        submitted_fields = event.get(
            "submitted_fields",
            {},
        )

        if submitted_fields:
            print(
                "    Submitted fields: "
                f"{submitted_fields}"
            )

    pause()


def view_honeypot_statistics_menu() -> None:
    """Display interaction statistics."""
    clear_screen()
    print_banner()
    print("\nCERBERUS HONEYPOT STATISTICS\n")

    try:
        statistics = honeypot_statistics()
    except HoneypotError as error:
        print(f"[!] Unable to calculate statistics: {error}")
        pause()
        return

    print(
        f"Total Interactions:  "
        f"{statistics['total_events']}"
    )
    print(
        f"Unique Sources:      "
        f"{statistics['unique_sources']}"
    )

    print("\nTop Sources:")

    if statistics["top_sources"]:
        for source, count in statistics["top_sources"]:
            print(f"  - {source:<18} {count}")
    else:
        print("  - None")

    print("\nHTTP Methods:")

    if statistics["methods"]:
        for method, count in statistics["methods"]:
            print(f"  - {method:<10} {count}")
    else:
        print("  - None")

    print("\nTop Requested Paths:")

    if statistics["top_paths"]:
        for path, count in statistics["top_paths"]:
            print(f"  - {path:<40} {count}")
    else:
        print("  - None")

    pause()


def export_honeypot_events_menu() -> None:
    """Export new honeypot events to Splunk."""
    clear_screen()
    print_banner()
    print("\nCERBERUS HONEYPOT — SPLUNK EXPORT\n")

    try:
        count, errors = export_new_events_to_splunk()
    except HoneypotError as error:
        print(f"[!] Honeypot export failed: {error}")
        pause()
        return

    print(f"[+] New events exported: {count}")

    if errors:
        print(f"[!] Errors: {len(errors)}")

        for error in errors:
            print(f"    - {error}")
    elif count == 0:
        print("[*] No new honeypot events required export.")
    else:
        print("[+] Export completed without errors.")

    pause()


def run_honeypot_menu() -> None:
    """Launch the Cerberus Honeypot submenu."""
    while True:
        clear_screen()
        print_banner()

        status = honeypot_status()

        print(
            f"""
CERBERUS HONEYPOT

Service Status:
{'RUNNING' if status['running'] else 'STOPPED'}
Port: {status['port']}

[1] Start Honeypot
[2] Stop Honeypot
[3] View Status
[4] View Recent Events
[5] View Statistics
[6] Export New Events to Splunk
[0] Return to Main Menu
"""
        )

        selection = input("honeypot > ").strip()

        if selection == "0":
            return

        actions = {
            "1": start_honeypot_menu,
            "2": stop_honeypot_menu,
            "3": view_honeypot_status_menu,
            "4": view_recent_honeypot_events_menu,
            "5": view_honeypot_statistics_menu,
            "6": export_honeypot_events_menu,
        }

        action = actions.get(selection)

        if action is None:
            print("\n[!] Invalid selection.")
            pause()
            continue

        action()

def show_system_status_menu() -> None:
    """Display Cerberus deployment-readiness checks."""
    clear_screen()
    print_banner()
    print("\nCERBERUS SYSTEM AND DEPENDENCY STATUS\n")

    checks = system_checks()

    print(
        f"{'Component':<22}"
        f"{'Status':<18}"
        f"Details"
    )
    print("-" * 90)

    for check in checks:
        print(
            f"{check.name:<22}"
            f"{check.status:<18}"
            f"{check.details}"
        )

    print("\n" + "=" * 90)

    if deployment_ready(checks):
        print(
            "[+] All required Cerberus dependencies "
            "are ready."
        )
    else:
        print(
            "[!] One or more required dependencies "
            "are missing."
        )

    print(
        "[i] Optional components may be unavailable "
        "without blocking core operation."
    )

    pause()


def reset_configuration_menu() -> None:
    """Reset persistent settings after confirmation."""
    clear_screen()
    print_banner()
    print("\nCERBERUS RESET CONFIGURATION\n")

    print(
        "This restores the non-secret Cerberus settings "
        "to their development defaults."
    )
    print(
        "Inventory, scans, reports, logs, and Git history "
        "will not be deleted."
    )

    confirmation = input(
        "\nType RESET to continue: "
    ).strip()

    if confirmation != "RESET":
        print("\n[*] Configuration reset cancelled.")
        pause()
        return

    reset_config()

    print("\n[+] Configuration restored to defaults.")
    pause()

def show_settings_menu() -> None:
    """Launch the persistent Cerberus Settings menu."""
    while True:
        clear_screen()
        print_banner()

        print(
            """
CERBERUS SETTINGS

[1] Network Settings
[2] Splunk Integration Settings
[3] Honeypot Settings
[4] Reporting Settings
[5] System and Dependency Status
[6] View Current Configuration
[7] Reset Configuration to Defaults
[0] Return to Main Menu
"""
        )

        selection = input("settings > ").strip()

        if selection == "0":
            return

        if selection == "1":
            clear_screen()
            print_banner()
            configure_network()
            pause()
            continue

        if selection == "2":
            clear_screen()
            print_banner()
            configure_splunk()
            pause()
            continue

        if selection == "3":
            clear_screen()
            print_banner()
            configure_honeypot()
            pause()
            continue

        if selection == "4":
            clear_screen()
            print_banner()
            configure_reporting()
            pause()
            continue

        if selection == "5":
            show_system_status_menu()
            continue

        if selection == "6":
            clear_screen()
            print_banner()
            view_configuration()
            print(f"\nConfiguration file: {CONFIG_FILE}")
            pause()
            continue

        if selection == "7":
            reset_configuration_menu()
            continue

        print("\n[!] Invalid selection.")
        pause()

def show_planned_feature(feature_name: str) -> None:
    """Display a placeholder for an upcoming Cerberus module."""
    clear_screen()
    print_banner()
    print(f"\n{feature_name}\n")
    print("[*] This module is not installed in the current build.")
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
        "6": run_device_intelligence_menu,
        "7": run_reporting_menu,
        "8": run_splunk_integration_menu,
        "9": run_honeypot_menu,
        "10": show_settings_menu,
    }

def run_menu() -> None:
    """Launch the interactive Cerberus appliance interface."""
    actions = build_menu_actions()

    while True:
        clear_screen()
        print_banner()
        print(
            """
--------- RECONNAISSANCE ---------

[1] Discover Network
[2] View Host Inventory
[3] Port Scanner
[4] Asset Profiler
[5] Web Enumeration

---------- INTELLIGENCE ----------

[6] Device Intelligence

----------- REPORTING ------------

[7] Reports

--------- SOC INTEGRATION --------

[8] Splunk Integration
[9] Honeypot

------------ SYSTEM --------------

[10] Settings

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
