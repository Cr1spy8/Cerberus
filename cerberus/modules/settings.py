from __future__ import annotations

import os
import shutil
import socket
import sys
import json
from dataclasses import dataclass
from copy import deepcopy
from pathlib import Path
from typing import Any
from cerberus import __version__

PROJECT_ROOT = Path(__file__).resolve().parents[2]
CONFIG_DIR = PROJECT_ROOT / "config"
CONFIG_FILE = CONFIG_DIR / "cerberus.json"


DEFAULT_CONFIG: dict[str, Any] = {
    "application": {
        "name": "Cerberus",
        "version": __version__,
    },

    "network": {
        "interface": "auto",
        "scan_profile": "standard",
    },

    "splunk": {
        "enabled": False,
        "hec_url": "http://192.168.233.129:8088",
        "index": "cerberus",
        "source": "cerberus",
        "sourcetype": "_json",
    },

    "honeypot": {
        "listen_address": "0.0.0.0",
        "port": 8081,
    },

    "reporting": {
        "output_directory": "reports",
        "default_format": "html",
    },
}


def ensure_config_directory() -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)


def save_config(config: dict[str, Any]) -> Path:
    ensure_config_directory()

    with CONFIG_FILE.open("w", encoding="utf-8") as handle:
        json.dump(config, handle, indent=2)

    return CONFIG_FILE


def load_config() -> dict[str, Any]:
    ensure_config_directory()

    if not CONFIG_FILE.exists():
        config = deepcopy(DEFAULT_CONFIG)
        save_config(config)
        return config

    try:
        with CONFIG_FILE.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (json.JSONDecodeError, OSError):
        config = deepcopy(DEFAULT_CONFIG)
        save_config(config)
        return config

    if not isinstance(data, dict):
        config = deepcopy(DEFAULT_CONFIG)
        save_config(config)
        return config

    return data


def reset_config() -> dict[str, Any]:
    config = deepcopy(DEFAULT_CONFIG)
    save_config(config)
    return config


def get_setting(
    section: str,
    key: str,
    default: Any = None,
) -> Any:
    config = load_config()

    section_data = config.get(section, {})

    if not isinstance(section_data, dict):
        return default

    return section_data.get(key, default)


def set_setting(
    section: str,
    key: str,
    value: Any,
) -> None:
    config = load_config()

    if section not in config or not isinstance(config[section], dict):
        config[section] = {}

    config[section][key] = value

    save_config(config)

def _prompt(
    label: str,
    current: Any,
) -> str:
    value = input(f"{label} [{current}]: ").strip()

    if not value:
        return str(current)

    return value


def _print_header(title: str) -> None:
    print()
    print("=" * 62)
    print(f"{title:^62}")
    print("=" * 62)
    print()


def view_configuration() -> None:
    config = load_config()

    _print_header("CERBERUS CURRENT CONFIGURATION")

    print("Application")
    print("-" * 62)
    print(f"Version:              {config['application']['version']}")
    print()

    print("Network")
    print("-" * 62)
    print(f"Interface:            {config['network']['interface']}")
    print(f"Scan profile:         {config['network']['scan_profile']}")
    print()

    print("Splunk")
    print("-" * 62)
    print(f"Enabled:              {config['splunk']['enabled']}")
    print(f"HEC URL:              {config['splunk']['hec_url']}")
    print(f"Index:                {config['splunk']['index']}")
    print(f"Source:               {config['splunk']['source']}")
    print(f"Sourcetype:           {config['splunk']['sourcetype']}")
    print("HEC token:            Environment variable")
    print()

    print("Honeypot")
    print("-" * 62)
    print(f"Listen address:       {config['honeypot']['listen_address']}")
    print(f"Port:                 {config['honeypot']['port']}")
    print()

    print("Reporting")
    print("-" * 62)
    print(f"Output directory:     {config['reporting']['output_directory']}")
    print(f"Default format:       {config['reporting']['default_format']}")


def configure_network() -> None:
    config = load_config()

    _print_header("CERBERUS NETWORK SETTINGS")

    interface = _prompt(
        "Network interface",
        config["network"]["interface"],
    )

    scan_profile = _prompt(
        "Default scan profile",
        config["network"]["scan_profile"],
    )

    config["network"]["interface"] = interface
    config["network"]["scan_profile"] = scan_profile

    save_config(config)

    print()
    print("[+] Network settings saved.")


def configure_splunk() -> None:
    config = load_config()

    _print_header("CERBERUS SPLUNK SETTINGS")

    current = config["splunk"]

    print(f"Current status: {'Enabled' if current['enabled'] else 'Disabled'}")
    print()

    enabled = input("Enable Splunk integration? [y/N]: ").strip().lower()

    if enabled in {"y", "yes"}:
        current["enabled"] = True
    elif enabled in {"n", "no"}:
        current["enabled"] = False

    current["hec_url"] = _prompt(
        "HEC URL",
        current["hec_url"],
    )

    current["index"] = _prompt(
        "Index",
        current["index"],
    )

    current["source"] = _prompt(
        "Source",
        current["source"],
    )

    current["sourcetype"] = _prompt(
        "Sourcetype",
        current["sourcetype"],
    )

    save_config(config)

    print()
    print("[+] Splunk settings saved.")
    print("[i] HEC token remains outside the configuration file.")


def configure_honeypot() -> None:
    config = load_config()

    _print_header("CERBERUS HONEYPOT SETTINGS")

    current = config["honeypot"]

    current["listen_address"] = _prompt(
        "Listen address",
        current["listen_address"],
    )

    port_value = _prompt(
        "Listen port",
        current["port"],
    )

    try:
        port = int(port_value)

        if not 1 <= port <= 65535:
            raise ValueError

        current["port"] = port

    except ValueError:
        print()
        print("[!] Invalid port. Existing value preserved.")

    save_config(config)

    print()
    print("[+] Honeypot settings saved.")


def configure_reporting() -> None:
    config = load_config()

    _print_header("CERBERUS REPORTING SETTINGS")

    current = config["reporting"]

    current["output_directory"] = _prompt(
        "Output directory",
        current["output_directory"],
    )

    report_format = _prompt(
        "Default format",
        current["default_format"],
    ).lower()

    if report_format in {"html", "json", "markdown"}:
        current["default_format"] = report_format
    else:
        print()
        print("[!] Unsupported format. Existing value preserved.")

    save_config(config)

    print()
    print("[+] Reporting settings saved.")

@dataclass
class SystemCheck:
    """One Cerberus deployment-readiness check."""

    name: str
    status: str
    details: str
    required: bool = True


def _command_version(
    command: list[str],
) -> str:
    """Return the first output line from a version command."""
    import subprocess

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=8,
        )
    except (
        OSError,
        subprocess.TimeoutExpired,
    ):
        return "Unavailable"

    output = (
        result.stdout.strip()
        or result.stderr.strip()
    )

    if not output:
        return "Installed"

    return output.splitlines()[0][:100]


def check_tcp_connection(
    hostname: str,
    port: int,
    timeout: float = 3.0,
) -> bool:
    """Test whether one TCP endpoint is reachable."""
    try:
        with socket.create_connection(
            (hostname, port),
            timeout=timeout,
        ):
            return True
    except (
        OSError,
        socket.timeout,
    ):
        return False


def parse_hec_endpoint(
    hec_url: str,
) -> tuple[str, int] | None:
    """Extract the hostname and port from an HEC URL."""
    from urllib.parse import urlparse

    try:
        parsed = urlparse(hec_url)
    except ValueError:
        return None

    if not parsed.hostname:
        return None

    if parsed.port is not None:
        port = parsed.port
    elif parsed.scheme == "https":
        port = 443
    else:
        port = 80

    return parsed.hostname, port


def system_checks() -> list[SystemCheck]:
    """Run Cerberus dependency and readiness checks."""
    config = load_config()
    checks: list[SystemCheck] = []

    python_version = (
        f"{sys.version_info.major}."
        f"{sys.version_info.minor}."
        f"{sys.version_info.micro}"
    )

    checks.append(
        SystemCheck(
            name="Python",
            status="OK",
            details=python_version,
        )
    )

    nmap_path = shutil.which("nmap")

    checks.append(
        SystemCheck(
            name="Nmap",
            status="OK" if nmap_path else "MISSING",
            details=(
                _command_version(["nmap", "--version"])
                if nmap_path
                else "Install the nmap package."
            ),
        )
    )

    ip_path = shutil.which("ip")

    checks.append(
        SystemCheck(
            name="Network Tools",
            status="OK" if ip_path else "MISSING",
            details=ip_path or "The ip command was not found.",
        )
    )

    inventory_path = PROJECT_ROOT / "inventory" / "hosts.json"

    checks.append(
        SystemCheck(
            name="Inventory",
            status=(
                "OK"
                if inventory_path.exists()
                else "NOT INITIALIZED"
            ),
            details=str(inventory_path),
            required=False,
        )
    )

    report_directory = (
        PROJECT_ROOT
        / str(
            config.get(
                "reporting",
                {},
            ).get(
                "output_directory",
                "reports",
            )
        )
    )

    try:
        report_directory.mkdir(
            parents=True,
            exist_ok=True,
        )

        directory_writable = os.access(
            report_directory,
            os.W_OK,
        )
    except OSError:
        directory_writable = False

    checks.append(
        SystemCheck(
            name="Report Directory",
            status=(
                "OK"
                if directory_writable
                else "FAILED"
            ),
            details=str(report_directory),
        )
    )

    token_available = bool(
        os.environ.get(
            "CERBERUS_HEC_TOKEN",
            "",
        ).strip()
    )

    checks.append(
        SystemCheck(
            name="Splunk Token",
            status=(
                "OK"
                if token_available
                else "NOT SET"
            ),
            details=(
                "CERBERUS_HEC_TOKEN is available."
                if token_available
                else "Token is not exported in this shell."
            ),
            required=False,
        )
    )

    splunk_config = config.get("splunk", {})
    hec_url = str(
        splunk_config.get(
            "hec_url",
            "",
        )
    )

    hec_endpoint = parse_hec_endpoint(hec_url)

    if hec_endpoint is None:
        hec_reachable = False
        hec_details = "Invalid HEC URL."
    else:
        hec_host, hec_port = hec_endpoint
        hec_reachable = check_tcp_connection(
            hec_host,
            hec_port,
        )
        hec_details = (
            f"{hec_host}:{hec_port}"
        )

    checks.append(
        SystemCheck(
            name="Splunk HEC",
            status=(
                "OK"
                if hec_reachable
                else "UNREACHABLE"
            ),
            details=hec_details,
            required=False,
        )
    )

    honeypot_port = int(
        config.get(
            "honeypot",
            {},
        ).get(
            "port",
            8081,
        )
    )

    checks.append(
        SystemCheck(
            name="Honeypot Port",
            status="READY",
            details=f"Configured for TCP {honeypot_port}.",
            required=False,
        )
    )

    return checks


def deployment_ready(
    checks: list[SystemCheck] | None = None,
) -> bool:
    """Return whether all required checks passed."""
    if checks is None:
        checks = system_checks()

    acceptable_statuses = {
        "OK",
        "READY",
    }

    return all(
        not check.required
        or check.status in acceptable_statuses
        for check in checks
    )
