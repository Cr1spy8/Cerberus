# Cerberus

> Portable penetration-testing and network-assessment appliance for authorized security testing, asset discovery, SOC integration, and cybersecurity lab environments.

---

## Overview

Cerberus is a modular cybersecurity platform designed to provide a centralized workflow for internal network reconnaissance, asset discovery, enumeration, device intelligence, reporting, honeypot monitoring, and defensive-security integration.

The project began as an experiment to determine whether inexpensive consumer networking hardware could be turned into a portable penetration-testing appliance. During development, the architecture evolved into a more capable design:

- A **TP-Link Archer C54** provides the portable network backbone and access layer.
- A dedicated **Linux system** runs the Cerberus application and security tooling.
- **Splunk** can receive structured Cerberus telemetry through the HTTP Event Collector.
- Persistent JSON storage maintains asset, scan, intelligence, and reporting data.

Cerberus is designed for cybersecurity education, lab use, internal assessments, and authorized penetration testing.

---

# Current Status

**Current Release Candidate:** `v1.0.0`

Cerberus v1 includes ten completed modules:

- ✅ Module 001 — Network Discovery
- ✅ Module 002 — Persistent Host Inventory
- ✅ Module 003 — Port Scanner
- ✅ Module 004 — Asset Profiler
- ✅ Module 005 — Web Enumeration
- ✅ Module 006 — Device Intelligence
- ✅ Module 007 — Reporting Engine
- ✅ Module 008 — Splunk Integration
- ✅ Module 009 — Honeypot
- ✅ Module 010 — Settings and Configuration

The application has also completed:

- Clean-install testing
- Fresh configuration initialization
- Runtime-data isolation
- Dependency validation
- Splunk HEC testing
- Honeypot testing
- Full end-to-end regression testing

---

# Core Workflow

Cerberus is designed as a connected assessment workflow rather than a collection of unrelated scripts.

```text
Network Discovery
        │
        ▼
Persistent Inventory
        │
        ▼
Port Scanner
        │
        ▼
Asset Profiler
        │
        ▼
Web Enumeration
        │
        ▼
Device Intelligence
        │
        ▼
Reporting Engine
        │
        ├────────────► Splunk
        │
        ▼
Honeypot Monitoring
