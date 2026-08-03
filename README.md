# Cerberus

> A portable penetration testing appliance built on a TP-Link Archer C54 router.

---

## Overview

Cerberus is a modular offensive security platform designed to transform inexpensive consumer networking hardware into a dedicated penetration testing appliance.

Rather than acting as a general-purpose Linux system, Cerberus provides a centralized interface for reconnaissance, asset discovery, enumeration, reporting, and future exploitation modules.

The long-term objective is to create a self-contained platform capable of performing internal network assessments, maintaining persistent asset inventories, integrating with defensive monitoring platforms such as Splunk, and serving as a practical cybersecurity learning environment.

---

# Current Status

Current Version: **v2.5**

Current Development Stage:

- ✅ Discovery Engine
- ✅ Persistent Host Inventory
- ✅ Interactive Appliance Interface
- 🚧 Port Scanner
- 🚧 Web Enumeration
- 🚧 SMB Enumeration
- 🚧 Reporting Engine
- 🚧 Honeypot Integration
- 🚧 Splunk Integration

---

# Current Features

## Network Discovery

- Automatic interface detection
- Automatic subnet identification
- Live host discovery using Nmap
- Structured JSON output
- Host discovery reasoning

---

## Persistent Inventory

Cerberus maintains a persistent inventory of every discovered host.

For every device discovered it stores:

- IP Address
- Hostname
- Discovery Status
- Discovery Reason
- First Seen
- Last Seen
- Number of Sightings

---

## Interactive Appliance

Cerberus now launches through a centralized menu.

```
=============================
 CERBERUS
 Portable Pentesting Appliance
=============================

1. Discover Network

2. View Host Inventory

3. Port Scanner

4. Web Enumeration

5. SMB Enumeration

6. Reports

7. Settings
```

Future modules will integrate directly into this interface.

---

# Directory Structure

```
Cerberus/
│
├── cerberus/
│   ├── cli.py
│   ├── menu.py
│   └── modules/
│       ├── discovery.py
│       └── inventory.py
│
├── config/
├── dashboard/
├── docs/
├── inventory/
├── payloads/
├── reports/
├── scans/
├── tests/
│
├── README.md
├── CHANGELOG.md
└── requirements.txt
```

---

# Roadmap

## Version 1.0

- Hardware identified
- Firmware researched
- SSH access
- Network configured
- Logging enabled
- Honeypot deployed
- Logs visible in Splunk
- Successful testing

---

## Planned Modules

### Reconnaissance

- Network Discovery
- Host Inventory
- Port Scanner
- OS Detection
- Service Enumeration

### Web

- HTTP Enumeration
- HTTPS Enumeration
- Directory Discovery
- Technology Detection

### Windows

- SMB Enumeration
- Share Discovery
- LDAP Enumeration
- Domain Information

### Reporting

- JSON Reports
- HTML Reports
- PDF Reports

### Integrations

- Splunk
- Syslog
- Honeypots

---

# Technology Stack

- Python 3
- Nmap
- JSON
- Git
- Kali Linux

Future integrations:

- Scapy
- Impacket
- Flask
- SQLite
- Splunk SDK

---

# Project Goals

Cerberus is intended to become a lightweight, modular penetration testing appliance capable of:

- Internal network reconnaissance
- Asset inventory
- Enumeration
- Security assessments
- Honeypot deployment
- Splunk integration
- Automated reporting

while remaining portable enough to operate from low-cost embedded hardware.

---

# License

Development Project

Built for cybersecurity education, research, and authorized penetration testing.
