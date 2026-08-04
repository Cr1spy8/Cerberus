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


## v2.8 — Web Enumeration

### Added

- Added Module 005: Web Enumeration.
- Added inventory-based web-target selection.
- Added HTTP and HTTPS response collection.
- Added redirect tracking.
- Added HTML page-title extraction.
- Added server and content-type identification.
- Added common HTTP security-header analysis.
- Added robots.txt collection.
- Added basic TLS protocol and certificate metadata.
- Added structured web-enumeration JSON storage.
- Added web intelligence enrichment to the persistent inventory.
- Integrated web enumeration into the Cerberus appliance menu.
## Cerberus v1 Module Roadmap

### Reconnaissance

- [x] Module 001 — Network Discovery
- [x] Module 002 — Persistent Host Inventory
- [x] Module 003 — Port Scanner
- [x] Module 004 — Asset Profiler
- [x] Module 005 — Web Enumeration

### Intelligence

- [ ] Module 006 — Device Intelligence

### Reporting

- [ ] Module 007 — Reporting Engine

### SOC Integration

- [ ] Module 008 — Splunk Integration
- [ ] Module 009 — Honeypot

### System

- [ ] Module 010 — Settings

## v1 Deployment Milestone

After all ten modules are complete, Cerberus will be packaged and deployed as a standalone appliance using:

- The TP-Link Archer C54 as the isolated network backbone
- A dedicated Linux system as the Cerberus processing platform
- Automatic startup
- Dependency installation
- Configuration persistence
- End-to-end acceptance testing

## v0.5.1-dev — Interface and Roadmap Refresh

### Changed

- Added the application version to the Cerberus banner.
- Reorganized the menu around reconnaissance, intelligence, reporting, SOC integration, and system functions.
- Replaced the planned DNS Intelligence module with Device Intelligence.
- Moved standalone SMB and DNS modules to the future roadmap.
- Replaced planned-feature labels with `Not Installed`.
- Established Settings as Module 010.
- Added an initial read-only Settings interface.
- Defined deployment as the milestone following completion of all ten v1 modules.
