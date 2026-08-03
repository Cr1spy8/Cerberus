# Changelog

## v0.1 - Project Initialization

### Added

- Initial project directory structure
- Hardware documentation templates
- Project goals document
- Research notes
- Version roadmap

### Notes

Project initialized following a documentation-first approach. No hardware modifications have been performed.


## v0.1.1

### Added

- Documented external hardware characteristics
- Recorded power specifications
- Recorded network interface layout
- Began hardware profiling


## v0.1.2

### Added

- Completed initial router setup
- Configured isolated lab environment
- Preserved factory firmware for analysis
- Deferred Internet connectivity pending hardware and firmware assessment


## v0.2.0

### Added

- Completed initial reconnaissance of the stock firmware interface.
- Cataloged available networking and system management modules.
- Identified key areas for future analysis (Backup & Restore, System Log, Administration, Diagnostics).
- Decided to analyze the factory firmware before considering replacement firmware.


## v0.2.1

### Added

- Performed initial network reconnaissance using Nmap.
- Identified exposed management services.
- Confirmed SSH, HTTP, and UPnP are accessible.
- Established baseline network attack surface.


## v0.2.2 - Firmware Reconnaissance

### Completed
- Enumerated network services with Nmap
- Confirmed OpenSSH 6.6.0 via banner grabbing
- Fingerprinted the HTTP interface with curl, Nikto, and WhatWeb
- Identified jQuery-based web interface
- Documented absence of HTTP server banner
- Exported baseline configuration for future comparison

### Next Objective
- Analyze the web interface using browser Developer Tools and Burp Suite.
- Download and inspect the factory firmware offline.


## v0.2.3

### Added

- Created the Cerberus Python package.
- Added a modular network-discovery engine.
- Added automatic interface and subnet detection.
- Added Nmap XML parsing.
- Added JSON scan-result storage.
- Added the initial Cerberus command-line interface.


## v2.5 — Interactive Appliance Interface

### Added

- Added a centralized interactive Cerberus menu.
- Integrated network discovery into the appliance interface.
- Integrated persistent host inventory viewing.
- Added placeholders for planned scanning, enumeration, reporting, and settings modules.
- Configured the interactive menu as the default Cerberus behavior.
- Added an optional system launcher for running Cerberus with a single command.

### Current Menu

1. Network Discovery
2. Host Inventory
3. Port Scanner — planned
4. Web Enumeration — planned
5. SMB Enumeration — planned
6. Reports — planned
7. Settings — planned


## v2.7 — Asset Profiler

### Added

- Added Module 004: Asset Profiler.
- Added reverse-hostname resolution.
- Added local-network MAC address collection.
- Added MAC vendor identification when available.
- Added service-based operating-system family inference.
- Added broad device-type classification.
- Added evidence-backed asset tags.
- Added structured asset-profile JSON storage.
- Added asset profile enrichment to the persistent inventory.
- Integrated the profiler into the Cerberus appliance menu.


