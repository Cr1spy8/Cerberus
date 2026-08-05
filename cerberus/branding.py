"""Shared Cerberus branding and application identity."""

from __future__ import annotations

from cerberus import __version__


PRODUCT_NAME = "CERBERUS"
PRODUCT_DESCRIPTION = "Portable Penetration Testing Appliance"
PROJECT_MOTTO = "Discover. Enumerate. Analyze. Report."


def terminal_banner() -> str:
    """Return the standard Cerberus terminal banner."""
    return "\n".join(
        [
            "=" * 62,
            f"{PRODUCT_NAME:^62}",
            f"{PRODUCT_DESCRIPTION:^62}",
            f"{PROJECT_MOTTO:^62}",
            f"{'Version ' + __version__:^62}",
            "=" * 62,
        ]
    )


def report_product_line() -> str:
    """Return the report branding line."""
    return f"{PRODUCT_NAME} — {PRODUCT_DESCRIPTION}"
