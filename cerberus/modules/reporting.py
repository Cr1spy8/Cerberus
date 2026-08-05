#!/usr/bin/env python3

from __future__ import annotations

import html
import json
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any
from cerberus import __version__
from cerberus.modules.inventory import (
    InventoryError,
    InventoryHost,
    load_inventory,
)
from cerberus.branding import (
    PRODUCT_DESCRIPTION,
    PRODUCT_NAME,
    PROJECT_MOTTO,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]
REPORT_DIRECTORY = PROJECT_ROOT / "reports"


class ReportingError(RuntimeError):
    """Raised when a Cerberus report cannot be generated."""


@dataclass
class ReportSummary:
    generated_at: str
    cerberus_version: str
    report_type: str
    network_name: str
    total_hosts: int
    active_hosts: int
    hosts_with_services: int
    hosts_with_web_services: int
    total_open_services: int
    risk_counts: dict[str, int]


@dataclass
class CerberusReport:
    summary: ReportSummary
    hosts: list[dict[str, Any]]


def normalize_host(host: InventoryHost) -> dict[str, Any]:
    """Convert an inventory host into a report-ready dictionary."""
    host_data = asdict(host)

    intelligence = host.intelligence or {}

    host_data["report_classification"] = intelligence.get(
        "classification",
        host.device_type,
    )

    host_data["report_operating_system"] = intelligence.get(
        "operating_system",
        host.operating_system,
    )

    host_data["risk_score"] = intelligence.get("risk_score", 0)
    host_data["risk_level"] = intelligence.get(
        "risk_level",
        "informational",
    )

    host_data["confidence_score"] = intelligence.get(
        "confidence_score",
        0,
    )

    host_data["findings"] = intelligence.get("findings", [])
    host_data["recommendations"] = intelligence.get(
        "recommendations",
        [],
    )

    return host_data


def build_summary(
    hosts: list[dict[str, Any]],
    report_type: str,
    network_name: str,
) -> ReportSummary:
    """Create network-level report statistics."""
    active_hosts = sum(
        1
        for host in hosts
        if host.get("status") == "up"
    )

    hosts_with_services = sum(
        1
        for host in hosts
        if host.get("services")
    )

    hosts_with_web_services = sum(
        1
        for host in hosts
        if host.get("web_services")
    )

    total_open_services = sum(
        len(host.get("services", []))
        for host in hosts
    )

    risk_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "informational": 0,
    }

    for host in hosts:
        level = str(
            host.get("risk_level", "informational")
        ).lower()

        if level not in risk_counts:
            level = "informational"

        risk_counts[level] += 1

    return ReportSummary(
        generated_at=datetime.now().astimezone().isoformat(),
        cerberus_version=__version__,
        report_type=report_type,
        network_name=network_name,
        total_hosts=len(hosts),
        active_hosts=active_hosts,
        hosts_with_services=hosts_with_services,
        hosts_with_web_services=hosts_with_web_services,
        total_open_services=total_open_services,
        risk_counts=risk_counts,
    )


def build_network_report(
    network_name: str = "Cerberus Assessment Network",
) -> CerberusReport:
    """Build a full report from every inventoried host."""
    try:
        inventory = load_inventory()
    except InventoryError as error:
        raise ReportingError(str(error)) from error

    if not inventory:
        raise ReportingError(
            "The inventory is empty. Run Network Discovery first."
        )

    hosts = [
        normalize_host(host)
        for host in sorted(
            inventory.values(),
            key=lambda item: tuple(
                int(part)
                for part in item.ip_address.split(".")
            ),
        )
    ]

    summary = build_summary(
        hosts=hosts,
        report_type="full_network",
        network_name=network_name,
    )

    return CerberusReport(
        summary=summary,
        hosts=hosts,
    )


def build_host_report(
    ip_address: str,
    network_name: str = "Cerberus Assessment Network",
) -> CerberusReport:
    """Build a report for one inventoried host."""
    try:
        inventory = load_inventory()
    except InventoryError as error:
        raise ReportingError(str(error)) from error

    host = inventory.get(ip_address)

    if host is None:
        raise ReportingError(
            f"{ip_address} does not exist in the inventory."
        )

    hosts = [normalize_host(host)]

    summary = build_summary(
        hosts=hosts,
        report_type="single_host",
        network_name=network_name,
    )

    return CerberusReport(
        summary=summary,
        hosts=hosts,
    )


def report_payload(
    report: CerberusReport,
) -> dict[str, Any]:
    """Convert a report object into serializable data."""
    return {
        "summary": asdict(report.summary),
        "hosts": report.hosts,
    }


def safe_filename(value: str) -> str:
    """Convert a value into a filesystem-safe report name."""
    return "".join(
        character
        if character.isalnum() or character in "-_."
        else "_"
        for character in value
    )


def report_basename(report: CerberusReport) -> str:
    """Generate a common filename for all report formats."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    if report.summary.report_type == "single_host":
        target = report.hosts[0]["ip_address"]
        return (
            f"cerberus_host_"
            f"{safe_filename(target)}_{timestamp}"
        )

    return f"cerberus_network_{timestamp}"


def save_json_report(
    report: CerberusReport,
    basename: str,
) -> Path:
    """Save a report as structured JSON."""
    REPORT_DIRECTORY.mkdir(parents=True, exist_ok=True)

    output_path = REPORT_DIRECTORY / f"{basename}.json"

    output_path.write_text(
        json.dumps(
            report_payload(report),
            indent=2,
        ),
        encoding="utf-8",
    )

    return output_path


def service_display(
    service: dict[str, Any],
) -> str:
    """Format one service for human-readable reports."""
    port = service.get("port", "?")
    protocol = service.get("protocol", "tcp")
    name = service.get("service", "unknown")

    version_parts = [
        str(service.get("product", "")).strip(),
        str(service.get("version", "")).strip(),
        str(service.get("extra_info", "")).strip(),
    ]

    version = " ".join(
        part for part in version_parts if part
    )

    value = f"{port}/{protocol} — {name}"

    if version:
        value += f" — {version}"

    return value


def render_markdown(report: CerberusReport) -> str:
    """Render a complete Markdown assessment report."""
    summary = report.summary

    lines = [
        "# Cerberus Assessment Report",
        "",
        f"**Generated:** {summary.generated_at}",
        f"**Cerberus Version:** {summary.cerberus_version}",
        f"**Report Type:** {summary.report_type}",
        f"**Network:** {summary.network_name}",
        "",
        "## Executive Summary",
        "",
        f"- Total inventoried hosts: {summary.total_hosts}",
        f"- Active hosts: {summary.active_hosts}",
        f"- Hosts with open services: "
        f"{summary.hosts_with_services}",
        f"- Hosts with web services: "
        f"{summary.hosts_with_web_services}",
        f"- Total recorded open services: "
        f"{summary.total_open_services}",
        "",
        "### Risk Distribution",
        "",
        f"- Critical: {summary.risk_counts['critical']}",
        f"- High: {summary.risk_counts['high']}",
        f"- Medium: {summary.risk_counts['medium']}",
        f"- Low: {summary.risk_counts['low']}",
        f"- Informational: "
        f"{summary.risk_counts['informational']}",
        "",
        "## Asset Summary",
        "",
        "| IP Address | Status | Classification | OS | Risk |",
        "|---|---|---|---|---|",
    ]

    for host in report.hosts:
        lines.append(
            "| "
            f"{host['ip_address']} | "
            f"{host.get('status', 'unknown')} | "
            f"{host.get('report_classification', 'unknown')} | "
            f"{host.get('report_operating_system', 'unknown')} | "
            f"{host.get('risk_level', 'informational')} "
            f"({host.get('risk_score', 0)}/100) |"
        )

    lines.extend(
        [
            "",
            "## Host Details",
            "",
        ]
    )

    for host in report.hosts:
        lines.extend(
            render_host_markdown(host)
        )

    lines.extend(
        [
            "",
            "## Assessment Notes",
            "",
            "- Observed facts originate from collected scan data.",
            "- Device classifications and operating-system "
            "families may be inferred.",
            "- Risk scores are Cerberus exposure assessments, "
            "not confirmed vulnerabilities.",
            "- Findings should be manually validated before "
            "being treated as final conclusions.",
            "",
        ]
    )

    return "\n".join(lines)


def render_host_markdown(
    host: dict[str, Any],
) -> list[str]:
    """Render one host section in Markdown."""
    lines = [
        f"### {host['ip_address']}",
        "",
        "#### Identity",
        "",
        f"- Hostname: {host.get('hostname') or 'Unknown'}",
        f"- MAC address: "
        f"{host.get('mac_address') or 'Unavailable'}",
        f"- Vendor: {host.get('vendor') or 'Unknown'}",
        f"- Classification: "
        f"{host.get('report_classification', 'unknown')}",
        f"- Operating system: "
        f"{host.get('report_operating_system', 'unknown')}",
        f"- Confidence: "
        f"{host.get('confidence_score', 0)}%",
        f"- Risk: {host.get('risk_level', 'informational')} "
        f"({host.get('risk_score', 0)}/100)",
        f"- First seen: {host.get('first_seen', '')}",
        f"- Last seen: {host.get('last_seen', '')}",
        "",
        "#### Open Services",
        "",
    ]

    services = host.get("services", [])

    if services:
        lines.extend(
            f"- {service_display(service)}"
            for service in services
        )
    else:
        lines.append("- No open services stored.")

    lines.extend(
        [
            "",
            "#### Web Services",
            "",
        ]
    )

    web_services = host.get("web_services", [])

    if web_services:
        for web_service in web_services:
            url = (
                web_service.get("final_url")
                or web_service.get("requested_url")
                or "Unknown URL"
            )

            lines.append(f"- {url}")
            lines.append(
                f"  - Status: "
                f"{web_service.get('status_code', 0)} "
                f"{web_service.get('reason', '')}".strip()
            )
            lines.append(
                f"  - Title: "
                f"{web_service.get('title') or 'Unknown'}"
            )
            lines.append(
                f"  - Server: "
                f"{web_service.get('server') or 'Not disclosed'}"
            )

            missing = web_service.get(
                "missing_security_headers",
                [],
            )

            if missing:
                lines.append(
                    "  - Missing security headers: "
                    + ", ".join(str(item) for item in missing)
                )
    else:
        lines.append("- No web services stored.")

    lines.extend(
        [
            "",
            "#### Findings",
            "",
        ]
    )

    findings = host.get("findings", [])

    if findings:
        for finding in findings:
            severity = str(
                finding.get("severity", "informational")
            ).upper()

            title = str(
                finding.get("title", "Untitled finding")
            )

            evidence = str(
                finding.get("evidence", "")
            )

            recommendation = str(
                finding.get("recommendation", "")
            )

            lines.append(
                f"- **{severity} — {title}**"
            )
            lines.append(
                f"  - Evidence: {evidence}"
            )
            lines.append(
                f"  - Recommendation: {recommendation}"
            )
    else:
        lines.append("- No Device Intelligence findings stored.")

    lines.extend(
        [
            "",
            "#### Recommendations",
            "",
        ]
    )

    recommendations = host.get("recommendations", [])

    if recommendations:
        lines.extend(
            f"- {recommendation}"
            for recommendation in recommendations
        )
    else:
        lines.append("- No recommendations stored.")

    lines.extend(
        [
            "",
            "---",
            "",
        ]
    )

    return lines


def save_markdown_report(
    report: CerberusReport,
    basename: str,
) -> Path:
    """Save a report as Markdown."""
    REPORT_DIRECTORY.mkdir(parents=True, exist_ok=True)

    output_path = REPORT_DIRECTORY / f"{basename}.md"

    output_path.write_text(
        render_markdown(report),
        encoding="utf-8",
    )

    return output_path

def overall_risk_level(
    risk_counts: dict[str, int],
) -> str:
    """Return the highest risk level represented in the report."""
    for level in (
        "critical",
        "high",
        "medium",
        "low",
        "informational",
    ):
        if risk_counts.get(level, 0) > 0:
            return level

    return "informational"


def total_findings(
    report: CerberusReport,
) -> int:
    """Count all Device Intelligence findings in a report."""
    return sum(
        len(host.get("findings", []))
        for host in report.hosts
    )


def total_recommendations(
    report: CerberusReport,
) -> int:
    """Count unique report recommendations."""
    recommendations: set[str] = set()

    for host in report.hosts:
        for recommendation in host.get(
            "recommendations",
            [],
        ):
            value = str(recommendation).strip()

            if value:
                recommendations.add(value)

    return len(recommendations)


def risk_css_class(level: str) -> str:
    """Return a safe CSS class name for one risk level."""
    normalized = level.lower()

    if normalized not in {
        "critical",
        "high",
        "medium",
        "low",
        "informational",
    }:
        return "informational"

    return normalized

def render_html(report: CerberusReport) -> str:
    """Render a standalone HTML report."""
    summary = report.summary
    overall_risk = overall_risk_level(
        summary.risk_counts
    )

    finding_count = total_findings(report)
    recommendation_count = total_recommendations(report)
    host_sections = "\n".join(
        render_host_html(host)
        for host in report.hosts
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Cerberus Assessment Report</title>

<style>
:root {{
    color-scheme: light;
}}

body {{
    font-family: Arial, Helvetica, sans-serif;
    max-width: 1100px;
    margin: 0 auto;
    padding: 32px;
    line-height: 1.5;
    background: #f2f3f5;
    color: #1c1c1c;
}}

header,
section {{
    background: white;
    padding: 24px;
    margin-bottom: 20px;
    border-radius: 9px;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.08);
}}

.brand {{
    letter-spacing: 0.12em;
    margin-bottom: 4px;
}}

.subtitle {{
    color: #555555;
    margin-top: 0;
}}

.motto {{
    font-style: italic;
    color: #666666;
}}

.summary-grid {{
    display: grid;
    grid-template-columns: repeat(
        auto-fit,
        minmax(170px, 1fr)
    );
    gap: 12px;
}}

.summary-card {{
    background: #f5f5f5;
    padding: 14px;
    border-radius: 6px;
}}

.summary-card strong {{
    display: block;
    margin-bottom: 5px;
}}

.overall-risk {{
    border-left: 7px solid #777777;
}}

.risk-critical {{
    color: #8b0000;
    font-weight: bold;
}}

.risk-high {{
    color: #b23a00;
    font-weight: bold;
}}

.risk-medium {{
    color: #9a6700;
    font-weight: bold;
}}

.risk-low {{
    color: #176b32;
    font-weight: bold;
}}

.risk-informational {{
    color: #3f4b59;
    font-weight: bold;
}}

.overall-risk.risk-critical {{
    border-left-color: #8b0000;
}}

.overall-risk.risk-high {{
    border-left-color: #b23a00;
}}

.overall-risk.risk-medium {{
    border-left-color: #9a6700;
}}

.overall-risk.risk-low {{
    border-left-color: #176b32;
}}

.overall-risk.risk-informational {{
    border-left-color: #3f4b59;
}}

table {{
    width: 100%;
    border-collapse: collapse;
}}

th,
td {{
    border: 1px solid #cccccc;
    padding: 10px;
    text-align: left;
    vertical-align: top;
}}

th {{
    background: #eeeeee;
}}

.finding {{
    padding: 12px;
    margin: 10px 0;
    background: #f7f7f7;
    border-left: 4px solid #777777;
}}

code {{
    background: #eeeeee;
    padding: 2px 5px;
}}

footer {{
    text-align: center;
    font-size: 0.9rem;
    margin-top: 30px;
    padding: 20px;
    color: #555555;
}}
</style>
</head>
<body>

<header>
<p class="brand"><strong>{html.escape(PRODUCT_NAME)}</strong></p>
<h1>Cerberus Assessment Report</h1>
<p class="subtitle">{html.escape(PRODUCT_DESCRIPTION)}</p>
<p class="motto">{html.escape(PROJECT_MOTTO)}</p>
<hr>
<p><strong>Generated:</strong> {html.escape(summary.generated_at)}</p>
<p><strong>Version:</strong> {html.escape(summary.cerberus_version)}</p>
<p><strong>Assessment:</strong> {html.escape(summary.network_name)}</p>
</header>

<section class="overall-risk risk-{risk_css_class(overall_risk)}">
<h2>Overall Assessment</h2>

<div class="summary-grid">

<div class="summary-card">
<strong>Overall Risk</strong>
<span class="risk-{risk_css_class(overall_risk)}">
{html.escape(overall_risk.upper())}
</span>
</div>

<div class="summary-card">
<strong>Hosts Analyzed</strong>
{summary.total_hosts}
</div>

<div class="summary-card">
<strong>Recorded Findings</strong>
{finding_count}
</div>

<div class="summary-card">
<strong>Recommendations</strong>
{recommendation_count}
</div>

<div class="summary-card">
<strong>Web-Enabled Hosts</strong>
{summary.hosts_with_web_services}
</div>

<div class="summary-card">
<strong>Open Services</strong>
{summary.total_open_services}
</div>

</div>

<p>
Cerberus identified
<strong>{summary.risk_counts['critical']}</strong>
critical,
<strong>{summary.risk_counts['high']}</strong>
high,
<strong>{summary.risk_counts['medium']}</strong>
medium, and
<strong>{summary.risk_counts['low']}</strong>
low-risk assets in the current inventory.
</p>
</section>

<section>
<h2>Executive Summary</h2>
<ul>
<li>Total hosts: {summary.total_hosts}</li>
<li>Active hosts: {summary.active_hosts}</li>
<li>Hosts with services: {summary.hosts_with_services}</li>
<li>Hosts with web services: {summary.hosts_with_web_services}</li>
<li>Total open services: {summary.total_open_services}</li>
</ul>
</section>

<section>
<h2>Risk Distribution</h2>
<table>
<tr>
<td class="risk-critical">
{summary.risk_counts['critical']}
</td>
<td class="risk-high">
{summary.risk_counts['high']}
</td>
<td class="risk-medium">
{summary.risk_counts['medium']}
</td>
<td class="risk-low">
{summary.risk_counts['low']}
</td>
<td class="risk-informational">
{summary.risk_counts['informational']}
</td>
</tr>
</table>
</section>

{host_sections}

<footer>
<strong>{html.escape(PRODUCT_NAME)}</strong><br>
{html.escape(PRODUCT_DESCRIPTION)}<br>
{html.escape(PROJECT_MOTTO)}<br>
Version {html.escape(summary.cerberus_version)}
</footer>

</body>
</html>
"""


def render_host_html(
    host: dict[str, Any],
) -> str:
    """Render one host section in HTML."""
    services = host.get("services", [])

    service_items = (
        "\n".join(
            f"<li>{html.escape(service_display(service))}</li>"
            for service in services
        )
        or "<li>No open services stored.</li>"
    )

    web_items: list[str] = []

    for web_service in host.get("web_services", []):
        url = (
            web_service.get("final_url")
            or web_service.get("requested_url")
            or "Unknown URL"
        )

        missing = web_service.get(
            "missing_security_headers",
            [],
        )

        missing_text = (
            ", ".join(str(item) for item in missing)
            if missing
            else "None recorded"
        )

        web_items.append(
            "<li>"
            f"<strong>{html.escape(str(url))}</strong><br>"
            f"Status: {web_service.get('status_code', 0)} "
            f"{html.escape(str(web_service.get('reason', '')))}<br>"
            f"Title: "
            f"{html.escape(str(web_service.get('title') or 'Unknown'))}<br>"
            f"Server: "
            f"{html.escape(str(web_service.get('server') or 'Not disclosed'))}<br>"
            f"Missing headers: {html.escape(missing_text)}"
            "</li>"
        )

    web_html = "\n".join(web_items) or (
        "<li>No web services stored.</li>"
    )

    finding_items: list[str] = []

    for finding in host.get("findings", []):
        severity = str(
            finding.get("severity", "informational")
        ).upper()

        title = str(
            finding.get("title", "Untitled finding")
        )

        evidence = str(
            finding.get("evidence", "")
        )

        recommendation = str(
            finding.get("recommendation", "")
        )

        finding_items.append(
            '<div class="finding">'
            f"<strong>{html.escape(severity)}: "
            f"{html.escape(title)}</strong>"
            f"<p>{html.escape(evidence)}</p>"
            f"<p><strong>Recommendation:</strong> "
            f"{html.escape(recommendation)}</p>"
            "</div>"
        )

    findings_html = "\n".join(finding_items) or (
        "<p>No Device Intelligence findings stored.</p>"
    )

    recommendations = host.get("recommendations", [])

    recommendation_html = (
        "\n".join(
            f"<li>{html.escape(str(item))}</li>"
            for item in recommendations
        )
        or "<li>No recommendations stored.</li>"
    )

    risk_level_value = str(
        host.get("risk_level", "informational")
    )

    return f"""
<section>
<h2>{html.escape(str(host['ip_address']))}</h2>

<h3>Identity</h3>
<table>
<tr><th>Hostname</th><td>{html.escape(str(host.get('hostname') or 'Unknown'))}</td></tr>
<tr><th>MAC Address</th><td>{html.escape(str(host.get('mac_address') or 'Unavailable'))}</td></tr>
<tr><th>Vendor</th><td>{html.escape(str(host.get('vendor') or 'Unknown'))}</td></tr>
<tr><th>Classification</th><td>{html.escape(str(host.get('report_classification', 'unknown')))}</td></tr>
<tr><th>Operating System</th><td>{html.escape(str(host.get('report_operating_system', 'unknown')))}</td></tr>
<tr><th>Confidence</th><td>{host.get('confidence_score', 0)}%</td></tr>
<tr><th>Risk</th><td class="risk-{html.escape(risk_level_value)}">{html.escape(risk_level_value.upper())} ({host.get('risk_score', 0)}/100)</td></tr>
</table>

<h3>Open Services</h3>
<ul>
{service_items}
</ul>

<h3>Web Services</h3>
<ul>
{web_html}
</ul>

<h3>Findings</h3>
{findings_html}

<h3>Recommendations</h3>
<ul>
{recommendation_html}
</ul>
</section>
"""


def save_html_report(
    report: CerberusReport,
    basename: str,
) -> Path:
    """Save a standalone HTML report."""
    REPORT_DIRECTORY.mkdir(parents=True, exist_ok=True)

    output_path = REPORT_DIRECTORY / f"{basename}.html"

    output_path.write_text(
        render_html(report),
        encoding="utf-8",
    )

    return output_path


def save_all_formats(
    report: CerberusReport,
) -> dict[str, Path]:
    """Generate JSON, Markdown, and HTML versions."""
    basename = report_basename(report)

    return {
        "json": save_json_report(report, basename),
        "markdown": save_markdown_report(report, basename),
        "html": save_html_report(report, basename),
    }


def list_existing_reports() -> list[Path]:
    """Return existing reports ordered newest first."""
    if not REPORT_DIRECTORY.exists():
        return []

    return sorted(
        (
            path
            for path in REPORT_DIRECTORY.iterdir()
            if path.is_file()
            and path.suffix in {".json", ".md", ".html"}
        ),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
