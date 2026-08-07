#!/usr/bin/env python3

"""Splunk HTTP Event Collector integration for Cerberus."""

from __future__ import annotations

import json
import os
import socket
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from cerberus.modules.settings import load_config
from cerberus import __version__
from cerberus.modules.inventory import (
    InventoryError,
    InventoryHost,
    load_inventory,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]
EXPORT_LOG_DIRECTORY = PROJECT_ROOT / "logs"
EXPORT_HISTORY_PATH = EXPORT_LOG_DIRECTORY / "splunk_exports.json"

DEFAULT_HEC_URL = (
    "http://192.168.233.129:8088/services/collector/event"
)
DEFAULT_INDEX = "cerberus"
DEFAULT_SOURCE = "cerberus"
DEFAULT_SOURCETYPE = "_json"


class SplunkIntegrationError(RuntimeError):
    """Raised when Cerberus cannot communicate with Splunk."""


@dataclass
class SplunkConfig:
    hec_url: str
    token: str
    index: str
    source: str
    sourcetype: str


@dataclass
class SplunkResponse:
    success: bool
    status_code: int
    message: str
    response_data: dict[str, Any]


@dataclass
class ExportHistoryEntry:
    timestamp: str
    export_type: str
    status: str
    event_count: int
    message: str


def load_splunk_config() -> SplunkConfig:
    settings = load_config()
    splunk_settings = settings.get("splunk", {})

    token = os.environ.get(
        "CERBERUS_HEC_TOKEN",
        "",
    ).strip()

    if not token:
        raise SplunkIntegrationError(
            "CERBERUS_HEC_TOKEN is not set in this shell."
        )

    hec_url = os.environ.get(
        "CERBERUS_HEC_URL",
        str(
            splunk_settings.get(
                "hec_url",
                DEFAULT_HEC_URL,
            )
        ),
    ).strip()
    hec_url = hec_url.rstrip("/")

    if not hec_url.endswith("/services/collector/event"):
        hec_url += "/services/collector/event"

    index = os.environ.get(
        "CERBERUS_SPLUNK_INDEX",
        str(
            splunk_settings.get(
                "index",
                DEFAULT_INDEX,
            )
        ),
    ).strip()

    source = os.environ.get(
        "CERBERUS_SPLUNK_SOURCE",
        str(
            splunk_settings.get(
                "source",
                DEFAULT_SOURCE,
            )
        ),
    ).strip()

    sourcetype = os.environ.get(
        "CERBERUS_SPLUNK_SOURCETYPE",
        str(
            splunk_settings.get(
                "sourcetype",
                DEFAULT_SOURCETYPE,
            )
        ),
    ).strip()

    return SplunkConfig(
        hec_url=hec_url,
        token=token,
        index=index,
        source=source,
        sourcetype=sourcetype,
    )


def build_hec_payload(
    config: SplunkConfig,
    event: dict[str, Any],
    *,
    host: str = "cerberus",
) -> dict[str, Any]:
    """Wrap a Cerberus event in Splunk HEC metadata."""
    return {
        "index": config.index,
        "source": config.source,
        "sourcetype": config.sourcetype,
        "host": host,
        "event": event,
    }


def send_event(
    config: SplunkConfig,
    event: dict[str, Any],
    *,
    host: str = "cerberus",
    timeout: float = 10.0,
) -> SplunkResponse:
    """Send one structured event to Splunk HEC."""
    payload = build_hec_payload(
        config,
        event,
        host=host,
    )

    request = Request(
        config.hec_url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Splunk {config.token}",
            "Content-Type": "application/json",
            "User-Agent": (
                f"Cerberus/{__version__} Splunk-Integration"
            ),
        },
        method="POST",
    )

    try:
        with urlopen(
            request,
            timeout=timeout,
        ) as response:
            response_body = response.read().decode(
                "utf-8",
                errors="replace",
            )

            try:
                response_data = json.loads(response_body)
            except json.JSONDecodeError:
                response_data = {
                    "raw_response": response_body,
                }

            success = (
                response.status == 200
                and response_data.get("code") == 0
            )

            return SplunkResponse(
                success=success,
                status_code=response.status,
                message=str(
                    response_data.get(
                        "text",
                        "Unknown Splunk response",
                    )
                ),
                response_data=response_data,
            )

    except HTTPError as error:
        response_body = error.read().decode(
            "utf-8",
            errors="replace",
        )

        try:
            response_data = json.loads(response_body)
        except json.JSONDecodeError:
            response_data = {
                "raw_response": response_body,
            }

        raise SplunkIntegrationError(
            "Splunk HEC returned "
            f"HTTP {error.code}: {response_data}"
        ) from error

    except (
        URLError,
        socket.timeout,
        TimeoutError,
        OSError,
    ) as error:
        raise SplunkIntegrationError(
            f"Unable to reach Splunk HEC: {error}"
        ) from error


def test_connection(
    config: SplunkConfig,
) -> SplunkResponse:
    """Send one Cerberus integration-test event."""
    event = {
        "event_type": "integration_test",
        "application": "cerberus",
        "module": "splunk_integration",
        "version": __version__,
        "status": "success",
        "message": (
            "Cerberus Python integration successfully "
            "reached Splunk HEC"
        ),
        "timestamp": datetime.now().astimezone().isoformat(),
    }

    response = send_event(
        config,
        event,
        host="cerberus",
    )

    record_export_history(
        ExportHistoryEntry(
            timestamp=datetime.now().astimezone().isoformat(),
            export_type="connection_test",
            status=(
                "success"
                if response.success
                else "failed"
            ),
            event_count=1,
            message=response.message,
        )
    )

    return response


def host_inventory_event(
    host: InventoryHost,
) -> dict[str, Any]:
    """Convert an inventory host to a Splunk inventory event."""
    host_data = asdict(host)
    intelligence = host.intelligence or {}

    return {
        "event_type": "host_inventory",
        "application": "cerberus",
        "module": "persistent_inventory",
        "version": __version__,
        "timestamp": datetime.now().astimezone().isoformat(),
        "asset": {
            "ip_address": host.ip_address,
            "hostname": host.hostname,
            "status": host.status,
            "reason": host.reason,
            "first_seen": host.first_seen,
            "last_seen": host.last_seen,
            "sightings": host.sightings,
            "mac_address": host.mac_address,
            "vendor": host.vendor,
            "device_type": host.device_type,
            "operating_system": host.operating_system,
            "tags": host.tags,
        },
        "service_count": len(host.services),
        "web_service_count": len(host.web_services),
        "classification": intelligence.get(
            "classification",
            host.device_type,
        ),
        "risk_level": intelligence.get(
            "risk_level",
            "informational",
        ),
        "risk_score": intelligence.get(
            "risk_score",
            0,
        ),
        "confidence_score": intelligence.get(
            "confidence_score",
            0,
        ),
        "inventory_record": host_data,
    }


def export_inventory(
    config: SplunkConfig,
) -> tuple[int, list[str]]:
    """
    Export one Splunk event per Cerberus inventory host.

    Returns:
        number of successful events and any failure messages
    """
    try:
        inventory = load_inventory()
    except InventoryError as error:
        raise SplunkIntegrationError(str(error)) from error

    if not inventory:
        raise SplunkIntegrationError(
            "Cerberus inventory is empty."
        )

    successful_events = 0
    errors: list[str] = []

    hosts = sorted(
        inventory.values(),
        key=lambda item: tuple(
            int(part)
            for part in item.ip_address.split(".")
        ),
    )

    for host in hosts:
        event = host_inventory_event(host)

        try:
            response = send_event(
                config,
                event,
                host=host.ip_address,
            )

            if response.success:
                successful_events += 1
            else:
                errors.append(
                    f"{host.ip_address}: {response.message}"
                )

        except SplunkIntegrationError as error:
            errors.append(
                f"{host.ip_address}: {error}"
            )

    status = (
        "success"
        if not errors
        else "partial_failure"
    )

    message = (
        f"Exported {successful_events} of "
        f"{len(hosts)} inventory hosts."
    )

    record_export_history(
        ExportHistoryEntry(
            timestamp=datetime.now().astimezone().isoformat(),
            export_type="host_inventory",
            status=status,
            event_count=successful_events,
            message=message,
        )
    )

    return successful_events, errors

def _sorted_inventory_hosts() -> list[InventoryHost]:
    """Return inventory hosts in deterministic IPv4 order."""
    try:
        inventory = load_inventory()
    except InventoryError as error:
        raise SplunkIntegrationError(str(error)) from error

    if not inventory:
        raise SplunkIntegrationError(
            "Cerberus inventory is empty."
        )

    return sorted(
        inventory.values(),
        key=lambda item: tuple(
            int(part)
            for part in item.ip_address.split(".")
        ),
    )


def export_device_intelligence(
    config: SplunkConfig,
) -> tuple[int, list[str]]:
    """Export one Device Intelligence event per analyzed host."""
    hosts = _sorted_inventory_hosts()

    successful_events = 0
    errors: list[str] = []
    eligible_hosts = 0

    for host in hosts:
        intelligence = host.intelligence or {}

        if not intelligence:
            continue

        eligible_hosts += 1

        event = {
            "event_type": "device_intelligence",
            "application": "cerberus",
            "module": "device_intelligence",
            "version": __version__,
            "timestamp": datetime.now().astimezone().isoformat(),
            "asset": {
                "ip_address": host.ip_address,
                "hostname": host.hostname,
                "mac_address": host.mac_address,
                "vendor": (
                    intelligence.get("vendor")
                    or host.vendor
                ),
                "device_type": host.device_type,
                "operating_system": (
                    intelligence.get("operating_system")
                    or host.operating_system
                ),
            },
            "classification": intelligence.get(
                "classification",
                "unknown",
            ),
            "confidence_score": intelligence.get(
                "confidence_score",
                0,
            ),
            "risk_score": intelligence.get(
                "risk_score",
                0,
            ),
            "risk_level": intelligence.get(
                "risk_level",
                "informational",
            ),
            "products": intelligence.get(
                "product_clues",
                [],
            ),
            "tags": intelligence.get(
                "tags",
                [],
            ),
            "evidence": intelligence.get(
                "evidence",
                [],
            ),
            "recommendations": intelligence.get(
                "recommendations",
                [],
            ),
            "intelligence_timestamp": intelligence.get(
                "timestamp",
                host.last_intelligence_scan,
            ),
        }

        try:
            response = send_event(
                config,
                event,
                host=host.ip_address,
            )

            if response.success:
                successful_events += 1
            else:
                errors.append(
                    f"{host.ip_address}: {response.message}"
                )

        except SplunkIntegrationError as error:
            errors.append(
                f"{host.ip_address}: {error}"
            )

    message = (
        f"Exported {successful_events} of "
        f"{eligible_hosts} Device Intelligence records."
    )

    record_export_history(
        ExportHistoryEntry(
            timestamp=datetime.now().astimezone().isoformat(),
            export_type="device_intelligence",
            status=(
                "success"
                if not errors
                else "partial_failure"
            ),
            event_count=successful_events,
            message=message,
        )
    )

    return successful_events, errors


def export_security_findings(
    config: SplunkConfig,
) -> tuple[int, list[str]]:
    """Export each Device Intelligence finding as its own event."""
    hosts = _sorted_inventory_hosts()

    successful_events = 0
    errors: list[str] = []
    total_findings = 0

    for host in hosts:
        intelligence = host.intelligence or {}
        findings = intelligence.get("findings", [])

        if not isinstance(findings, list):
            continue

        for finding in findings:
            if not isinstance(finding, dict):
                continue

            total_findings += 1

            event = {
                "event_type": "security_finding",
                "application": "cerberus",
                "module": "device_intelligence",
                "version": __version__,
                "timestamp": (
                    datetime.now()
                    .astimezone()
                    .isoformat()
                ),
                "asset": {
                    "ip_address": host.ip_address,
                    "hostname": host.hostname,
                    "classification": intelligence.get(
                        "classification",
                        "unknown",
                    ),
                },
                "severity": finding.get(
                    "severity",
                    "informational",
                ),
                "title": finding.get(
                    "title",
                    "Untitled finding",
                ),
                "evidence": finding.get(
                    "evidence",
                    "",
                ),
                "recommendation": finding.get(
                    "recommendation",
                    "",
                ),
                "asset_risk_level": intelligence.get(
                    "risk_level",
                    "informational",
                ),
                "asset_risk_score": intelligence.get(
                    "risk_score",
                    0,
                ),
            }

            try:
                response = send_event(
                    config,
                    event,
                    host=host.ip_address,
                )

                if response.success:
                    successful_events += 1
                else:
                    errors.append(
                        f"{host.ip_address}: "
                        f"{response.message}"
                    )

            except SplunkIntegrationError as error:
                errors.append(
                    f"{host.ip_address}: {error}"
                )

    message = (
        f"Exported {successful_events} of "
        f"{total_findings} security findings."
    )

    record_export_history(
        ExportHistoryEntry(
            timestamp=datetime.now().astimezone().isoformat(),
            export_type="security_findings",
            status=(
                "success"
                if not errors
                else "partial_failure"
            ),
            event_count=successful_events,
            message=message,
        )
    )

    return successful_events, errors


def export_assessment_summary(
    config: SplunkConfig,
) -> tuple[int, list[str]]:
    """Export a network-wide Cerberus assessment summary."""
    hosts = _sorted_inventory_hosts()

    active_hosts = sum(
        1
        for host in hosts
        if host.status.lower() == "up"
    )

    hosts_with_services = sum(
        1
        for host in hosts
        if host.services
    )

    hosts_with_web_services = sum(
        1
        for host in hosts
        if host.web_services
    )

    total_open_services = sum(
        len(host.services)
        for host in hosts
    )

    severity_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "informational": 0,
    }

    total_findings = 0

    for host in hosts:
        intelligence = host.intelligence or {}

        for finding in intelligence.get(
            "findings",
            [],
        ):
            if not isinstance(finding, dict):
                continue

            total_findings += 1

            severity = str(
                finding.get(
                    "severity",
                    "informational",
                )
            ).lower()

            if severity not in severity_counts:
                severity = "informational"

            severity_counts[severity] += 1

    event = {
        "event_type": "assessment_summary",
        "application": "cerberus",
        "module": "reporting",
        "version": __version__,
        "timestamp": datetime.now().astimezone().isoformat(),
        "summary": {
            "total_hosts": len(hosts),
            "active_hosts": active_hosts,
            "hosts_with_services": hosts_with_services,
            "hosts_with_web_services": (
                hosts_with_web_services
            ),
            "total_open_services": total_open_services,
            "total_findings": total_findings,
        },
        "risk_distribution": severity_counts,
    }

    errors: list[str] = []

    try:
        response = send_event(
            config,
            event,
            host="cerberus",
        )

        successful_events = (
            1 if response.success else 0
        )

        if not response.success:
            errors.append(response.message)

    except SplunkIntegrationError as error:
        successful_events = 0
        errors.append(str(error))

    record_export_history(
        ExportHistoryEntry(
            timestamp=datetime.now().astimezone().isoformat(),
            export_type="assessment_summary",
            status=(
                "success"
                if not errors
                else "failed"
            ),
            event_count=successful_events,
            message=(
                "Network assessment summary exported."
                if successful_events
                else "Assessment summary export failed."
            ),
        )
    )

    return successful_events, errors

def export_all(
    config: SplunkConfig,
) -> dict[str, tuple[int, list[str]]]:
    """Export all currently supported Cerberus datasets."""
    results = {}

    results["host_inventory"] = export_inventory(
        config
    )

    results["device_intelligence"] = (
        export_device_intelligence(config)
    )

    results["security_findings"] = (
        export_security_findings(config)
    )

    results["assessment_summary"] = (
        export_assessment_summary(config)
    )

    return results

def load_export_history() -> list[dict[str, Any]]:
    """Load prior Splunk export history."""
    if not EXPORT_HISTORY_PATH.exists():
        return []

    try:
        raw_data = json.loads(
            EXPORT_HISTORY_PATH.read_text(
                encoding="utf-8"
            )
        )
    except (
        OSError,
        json.JSONDecodeError,
    ):
        return []

    if not isinstance(raw_data, list):
        return []

    return raw_data


def record_export_history(
    entry: ExportHistoryEntry,
) -> None:
    """Append one Splunk export record to local history."""
    EXPORT_LOG_DIRECTORY.mkdir(
        parents=True,
        exist_ok=True,
    )

    history = load_export_history()
    history.append(asdict(entry))

    EXPORT_HISTORY_PATH.write_text(
        json.dumps(
            history[-500:],
            indent=2,
        ),
        encoding="utf-8",
    )
