# Changelog

## v1.0.0 — Initial Stable Release

### Added

- Completed Module 001: Network Discovery.
- Completed Module 002: Persistent Host Inventory.
- Completed Module 003: Port Scanner.
- Completed Module 004: Asset Profiler.
- Completed Module 005: Web Enumeration.
- Completed Module 006: Device Intelligence.
- Completed Module 007: Reporting Engine.
- Completed Module 008: Splunk Integration.
- Completed Module 009: Honeypot.
- Completed Module 010: Settings and Configuration.

### Network Discovery

- Added automatic interface detection.
- Added local subnet identification.
- Added Nmap-based host discovery.
- Added structured JSON discovery results.
- Added persistent discovery history.
- Added automatic inventory updates.

### Persistent Inventory

- Added first-seen and last-seen tracking.
- Added host sighting counters.
- Added persistent service storage.
- Added profiling, web-enumeration, and intelligence enrichment.
- Added structured JSON host records.

### Port Scanner

- Added inventory-based target selection.
- Added Nmap TCP scanning.
- Added service and version detection.
- Added structured scan output.
- Added inventory enrichment.

### Asset Profiler

- Added MAC and vendor enrichment.
- Added device-type classification.
- Added operating-system-family inference.
- Added evidence-based asset tags.

### Web Enumeration

- Added HTTP and HTTPS enumeration.
- Added response-status and redirect tracking.
- Added title and server-header collection.
- Added security-header analysis.
- Added robots.txt collection.
- Added basic TLS metadata.
- Added structured web-enumeration results.

### Device Intelligence

- Added evidence-based device classification.
- Added confidence scoring.
- Added exposure-based risk scoring.
- Added security findings and recommendations.
- Added structured intelligence storage.
- Added persistent inventory enrichment.

### Reporting

- Added single-host assessment reports.
- Added full-network assessment reports.
- Added JSON output.
- Added Markdown output.
- Added branded HTML output.
- Added Executive Summary.
- Added Overall Assessment.
- Added Risk Distribution.
- Added per-host findings and recommendations.

### Splunk Integration

- Added HTTP Event Collector integration.
- Added HEC connection testing.
- Added host-inventory export.
- Added Device Intelligence export.
- Added security-finding export.
- Added assessment-summary export.
- Added full-dataset export.
- Added local export-history tracking.
- Added support for structured event types:
  - `integration_test`
  - `host_inventory`
  - `device_intelligence`
  - `security_finding`
  - `assessment_summary`
  - `honeypot_interaction`
- Added environment-variable-based HEC token handling.

### Honeypot

- Added controlled HTTP management honeypot.
- Added background service start/stop controls.
- Added recent-event viewing.
- Added interaction statistics.
- Added JSONL event logging.
- Added source IP, source port, HTTP method, path, and user-agent capture.
- Added password and token redaction.
- Added incremental Splunk export support.

### Settings and Configuration

- Added persistent application configuration.
- Added network settings.
- Added Splunk HEC settings.
- Added honeypot settings.
- Added reporting settings.
- Added configuration reset.
- Added deployment-readiness and dependency checks.
- Added local configuration template handling.
- Added environment-variable support for secrets.

### Deployment

- Added hardened `install.sh`.
- Added runtime-directory initialization.
- Added clean configuration bootstrapping.
- Added dependency validation.
- Added Python source compilation validation.
- Added `~/bin/cerberus` launcher installation.
- Added clean-install and deployment testing.
- Added runtime-data isolation through `.gitignore`.
- Added deployment-specific configuration templates.

### Security Improvements

- Removed Python cache files from source control.
- Removed generated scans, reports, logs, and inventory from source control.
- Added secret-safe HEC token handling.
- Added credential redaction in honeypot logging.
- Added ignored local configuration.
- Added tracked `cerberus.example.json` deployment template.

### Fixed

- Fixed Splunk token loading during clean deployment.
- Fixed Splunk HEC endpoint construction.
- Fixed deployment-specific HEC configuration handling.
- Fixed multiple Python indentation and syntax issues discovered during modular development.
- Fixed inventory enrichment behavior across scan and intelligence modules.

### Validated

Cerberus v1.0.0 completed clean-deployment and regression testing covering:

- Fresh Git clone
- Fresh installer execution
- Launcher installation
- Configuration initialization
- Network discovery
- Host inventory
- Port scanning
- Asset profiling
- Web enumeration
- Device Intelligence
- Report generation
- Splunk HEC connectivity
- Full Splunk export
- Honeypot operation
- Settings persistence
- Dependency checks
- Runtime-data isolation
