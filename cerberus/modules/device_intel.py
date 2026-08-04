#!/usr/bin/env python3

from __future__ import annotations

import ipaddress
import json
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path

from cerberus.modules.inventory import InventoryHost


PROJECT_ROOT = Path(__file__).resolve().parents[2]
INTELLIGENCE_DIRECTORY = PROJECT_ROOT / "scans" / "intelligence"


class DeviceIntelligenceError(RuntimeError):
    """Raised when Device Intelligence cannot be completed."""


@dataclass
class IntelligenceFinding:
    severity: str
    title: str
    evidence: str
    recommendation: str


@dataclass
class DeviceIntelligenceResult:
    timestamp: str
    ip_address: str
    classification: str
    operating_system: str
    vendor: str
    product_clues: list[str]
    confidence_score: int
    risk_score: int
    risk_level: str
    tags: list[str]
    evidence: list[str]
    findings: list[IntelligenceFinding]
    recommendations: list[str]


def validate_target(target: str) -> str:
    """Validate and normalize one IPv4 address."""
    try:
        address = ipaddress.ip_address(target)
    except ValueError as error:
        raise DeviceIntelligenceError(
            f"Invalid IP address: {target}"
        ) from error

    if address.version != 4:
        raise DeviceIntelligenceError(
            "Module 006 currently supports IPv4 only."
        )

    return str(address)


def get_ports(host: InventoryHost) -> set[int]:
    """Return known open port numbers."""
    ports: set[int] = set()

    for service in host.services:
        raw_port = service.get("port")

        try:
            ports.add(int(raw_port))
        except (TypeError, ValueError):
            continue

    return ports


def get_service_names(host: InventoryHost) -> set[str]:
    """Return normalized service names."""
    names: set[str] = set()

    for service in host.services:
        name = str(service.get("service", "")).strip().lower()

        if name:
            names.add(name)

    return names


def get_service_products(host: InventoryHost) -> list[str]:
    """Collect product and version clues from port scans."""
    clues: set[str] = set()

    for service in host.services:
        product = str(service.get("product", "")).strip()
        version = str(service.get("version", "")).strip()
        extra_info = str(service.get("extra_info", "")).strip()

        combined = " ".join(
            part
            for part in (product, version, extra_info)
            if part
        ).strip()

        if combined:
            clues.add(combined)

    return sorted(clues)


def get_web_clues(host: InventoryHost) -> list[str]:
    """Collect useful web-server identity clues."""
    clues: set[str] = set()

    for web_service in host.web_services:
        title = str(web_service.get("title", "")).strip()
        server = str(web_service.get("server", "")).strip()
        final_url = str(web_service.get("final_url", "")).strip()

        if title:
            clues.add(f"Web title: {title}")

        if server:
            clues.add(f"Web server: {server}")

        if final_url:
            clues.add(f"Web endpoint: {final_url}")

    return sorted(clues)


def classify_device(
    host: InventoryHost,
    ports: set[int],
    service_names: set[str],
    product_clues: list[str],
    web_clues: list[str],
) -> tuple[str, list[str], int]:
    """
    Infer a broad device classification.

    Returns:
        classification, evidence, confidence points
    """
    evidence: list[str] = []
    score = 0

    product_text = " ".join(product_clues).lower()
    web_text = " ".join(web_clues).lower()
    vendor_text = host.vendor.lower()

    gateway_indicators = {
        53,
        67,
        68,
    }

    if (
        ports & gateway_indicators
        and ports & {80, 443, 8080, 8443}
    ):
        evidence.append(
            "DNS/DHCP and web-management services were observed."
        )
        score += 55
        return "router_or_gateway", evidence, score

    if any(
        keyword in vendor_text
        for keyword in (
            "tp-link",
            "netgear",
            "cisco",
            "ubiquiti",
            "arris",
            "linksys",
        )
    ):
        evidence.append(
            f"Network-device vendor identified as {host.vendor}."
        )
        score += 45
        return "network_device", evidence, score

    if ports & {135, 139, 445, 3389, 5985, 5986}:
        evidence.append(
            "Windows-associated network services were observed."
        )
        score += 60
        return "windows_host_or_server", evidence, score

    if ports & {22, 111, 2049}:
        evidence.append(
            "SSH or Unix-associated infrastructure services were observed."
        )
        score += 45

        if ports & {80, 443, 8080, 8443}:
            evidence.append(
                "A web-management or application service was also observed."
            )
            score += 15
            return "linux_server_or_network_device", evidence, score

        return "linux_or_unix_host", evidence, score

    if ports & {80, 443, 8080, 8443}:
        evidence.append("One or more web services were observed.")
        score += 35

        if any(
            word in web_text
            for word in (
                "router",
                "gateway",
                "admin",
                "management",
            )
        ):
            evidence.append(
                "The web interface contains management-device terminology."
            )
            score += 25
            return "web_managed_device", evidence, score

        return "web_enabled_host", evidence, score

    if any(
        keyword in product_text
        for keyword in (
            "printer",
            "camera",
            "nas",
            "synology",
            "qnap",
        )
    ):
        evidence.append(
            "Service-product banners suggest a specialized appliance."
        )
        score += 45
        return "specialized_appliance", evidence, score

    if host.device_type != "unknown":
        evidence.append(
            f"Asset Profiler previously classified the host as "
            f"{host.device_type}."
        )
        score += 30
        return host.device_type, evidence, score

    return "unknown", evidence, score


def infer_operating_system(
    host: InventoryHost,
    ports: set[int],
    product_clues: list[str],
) -> tuple[str, list[str], int]:
    """Infer a broad operating-system family."""
    evidence: list[str] = []
    score = 0
    products = " ".join(product_clues).lower()

    if ports & {135, 139, 445, 3389, 5985, 5986}:
        evidence.append(
            "Windows-associated ports strongly suggest Microsoft Windows."
        )
        score += 70
        return "windows", evidence, score

    if any(
        keyword in products
        for keyword in (
            "microsoft",
            "windows",
            "iis",
        )
    ):
        evidence.append(
            "Service banners contain Microsoft or Windows indicators."
        )
        score += 65
        return "windows", evidence, score

    if ports & {22, 111, 2049}:
        evidence.append(
            "SSH, RPC, or NFS services suggest Linux or Unix."
        )
        score += 50
        return "linux_or_unix", evidence, score

    if any(
        keyword in products
        for keyword in (
            "openssh",
            "ubuntu",
            "debian",
            "linux",
            "apache",
            "nginx",
            "busybox",
            "dropbear",
        )
    ):
        evidence.append(
            "Service banners contain Linux, Unix, or embedded-Linux clues."
        )
        score += 55

        if "busybox" in products or "dropbear" in products:
            return "embedded_linux", evidence, score + 15

        return "linux_or_unix", evidence, score

    if host.operating_system != "unknown":
        evidence.append(
            f"Asset Profiler previously inferred "
            f"{host.operating_system}."
        )
        score += 25
        return host.operating_system, evidence, score

    return "unknown", evidence, score


def analyze_risk(
    host: InventoryHost,
    ports: set[int],
) -> tuple[int, list[IntelligenceFinding]]:
    """Create a simple evidence-based exposure risk score."""
    findings: list[IntelligenceFinding] = []
    score = 0

    risky_services = {
        21: (
            "FTP service exposed",
            "FTP may transmit credentials and data without encryption.",
            "Prefer SFTP or another encrypted transfer protocol.",
            15,
        ),
        23: (
            "Telnet service exposed",
            "Telnet provides unencrypted remote administration.",
            "Disable Telnet and use SSH instead.",
            25,
        ),
        69: (
            "TFTP service exposed",
            "TFTP commonly lacks authentication and encryption.",
            "Restrict or disable TFTP when it is not required.",
            15,
        ),
        445: (
            "SMB service exposed",
            "SMB increases attack surface and may expose shares or identity data.",
            "Limit SMB access and verify signing and protocol versions.",
            10,
        ),
        3389: (
            "Remote Desktop exposed",
            "RDP is a high-value remote-access service.",
            "Restrict access, require MFA where possible, and monitor authentication.",
            15,
        ),
        5900: (
            "VNC service exposed",
            "VNC can provide remote graphical access.",
            "Restrict VNC and require strong encrypted authentication.",
            15,
        ),
    }

    for port, (
        title,
        evidence,
        recommendation,
        points,
    ) in risky_services.items():
        if port not in ports:
            continue

        score += points
        findings.append(
            IntelligenceFinding(
                severity=(
                    "high"
                    if points >= 20
                    else "medium"
                ),
                title=title,
                evidence=evidence,
                recommendation=recommendation,
            )
        )

    for web_service in host.web_services:
        missing_headers = web_service.get(
            "missing_security_headers",
            [],
        )

        if isinstance(missing_headers, list) and missing_headers:
            score += min(len(missing_headers) * 2, 12)

            findings.append(
                IntelligenceFinding(
                    severity="low",
                    title="Web security headers missing",
                    evidence=(
                        "Missing headers: "
                        + ", ".join(
                            str(header)
                            for header in missing_headers
                        )
                    ),
                    recommendation=(
                        "Review whether appropriate browser security "
                        "headers can be enabled."
                    ),
                )
            )

        server = str(
            web_service.get("server", "")
        ).strip()

        if server:
            findings.append(
                IntelligenceFinding(
                    severity="informational",
                    title="Web server banner disclosed",
                    evidence=f"Server header: {server}",
                    recommendation=(
                        "Consider reducing unnecessary version disclosure."
                    ),
                )
            )
            score += 3

    if len(ports) >= 10:
        score += 10
        findings.append(
            IntelligenceFinding(
                severity="medium",
                title="Broad service exposure",
                evidence=(
                    f"{len(ports)} open services are stored "
                    "for this host."
                ),
                recommendation=(
                    "Confirm that every exposed service is required."
                ),
            )
        )

    return min(score, 100), findings


def risk_level(score: int) -> str:
    """Convert a numeric score to a readable level."""
    if score >= 70:
        return "critical"

    if score >= 45:
        return "high"

    if score >= 20:
        return "medium"

    if score > 0:
        return "low"

    return "informational"


def build_recommendations(
    classification: str,
    findings: list[IntelligenceFinding],
) -> list[str]:
    """Create a deduplicated recommendation list."""
    recommendations = {
        finding.recommendation
        for finding in findings
        if finding.recommendation
    }

    if classification in {
        "router_or_gateway",
        "network_device",
        "web_managed_device",
    }:
        recommendations.update(
            {
                "Verify that the device is running current firmware.",
                "Keep remote administration disabled unless explicitly required.",
                "Disable unnecessary services such as UPnP, Telnet, or WPS.",
            }
        )

    return sorted(recommendations)


def analyze_device(
    host: InventoryHost,
) -> DeviceIntelligenceResult:
    """Create a complete Device Intelligence assessment."""
    target = validate_target(host.ip_address)
    ports = get_ports(host)
    service_names = get_service_names(host)
    product_clues = get_service_products(host)
    web_clues = get_web_clues(host)

    classification, device_evidence, device_confidence = (
        classify_device(
            host,
            ports,
            service_names,
            product_clues,
            web_clues,
        )
    )

    operating_system, os_evidence, os_confidence = (
        infer_operating_system(
            host,
            ports,
            product_clues,
        )
    )

    risk_score, findings = analyze_risk(host, ports)

    evidence = (
        device_evidence
        + os_evidence
        + product_clues
        + web_clues
    )

    confidence_score = min(
        max(device_confidence, os_confidence),
        100,
    )

    tags = sorted(
        {
            f"class:{classification}",
            f"os:{operating_system}",
            f"risk:{risk_level(risk_score)}",
            *(
                {f"vendor:{host.vendor.lower()}"}
                if host.vendor
                else set()
            ),
        }
    )

    return DeviceIntelligenceResult(
        timestamp=datetime.now().astimezone().isoformat(),
        ip_address=target,
        classification=classification,
        operating_system=operating_system,
        vendor=host.vendor,
        product_clues=product_clues + web_clues,
        confidence_score=confidence_score,
        risk_score=risk_score,
        risk_level=risk_level(risk_score),
        tags=tags,
        evidence=evidence,
        findings=findings,
        recommendations=build_recommendations(
            classification,
            findings,
        ),
    )


def save_device_intelligence(
    result: DeviceIntelligenceResult,
) -> Path:
    """Save Device Intelligence results as JSON."""
    INTELLIGENCE_DIRECTORY.mkdir(
        parents=True,
        exist_ok=True,
    )

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = (
        INTELLIGENCE_DIRECTORY
        / f"intelligence_{result.ip_address}_{timestamp}.json"
    )

    output_path.write_text(
        json.dumps(asdict(result), indent=2),
        encoding="utf-8",
    )

    return output_path
