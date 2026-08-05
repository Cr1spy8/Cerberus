# Cerberus Assessment Report

**Generated:** 2026-08-05T11:18:12.139663-04:00
**Cerberus Version:** 0.7.1-dev
**Report Type:** full_network
**Network:** 192.168.233.135

## Executive Summary

- Total inventoried hosts: 4
- Active hosts: 4
- Hosts with open services: 1
- Hosts with web services: 1
- Total recorded open services: 1

### Risk Distribution

- Critical: 0
- High: 0
- Medium: 0
- Low: 1
- Informational: 3

## Asset Summary

| IP Address | Status | Classification | OS | Risk |
|---|---|---|---|---|
| 192.168.233.1 | up | unknown | unknown | informational (0/100) |
| 192.168.233.2 | up | unknown | unknown | informational (0/100) |
| 192.168.233.135 | up | web_enabled_host | unknown | low (15/100) |
| 192.168.233.254 | up | unknown | unknown | informational (0/100) |

## Host Details

### 192.168.233.1

#### Identity

- Hostname: Unknown
- MAC address: Unavailable
- Vendor: Unknown
- Classification: unknown
- Operating system: unknown
- Confidence: 0%
- Risk: informational (0/100)
- First seen: 2026-08-03T18:04:32.880807-04:00
- Last seen: 2026-08-04T15:05:55.200895-04:00

#### Open Services

- No open services stored.

#### Web Services

- No web services stored.

#### Findings

- No Device Intelligence findings stored.

#### Recommendations

- No recommendations stored.

---

### 192.168.233.2

#### Identity

- Hostname: Unknown
- MAC address: Unavailable
- Vendor: Unknown
- Classification: unknown
- Operating system: unknown
- Confidence: 0%
- Risk: informational (0/100)
- First seen: 2026-08-03T18:04:32.880807-04:00
- Last seen: 2026-08-04T15:05:55.200895-04:00

#### Open Services

- No open services stored.

#### Web Services

- No web services stored.

#### Findings

- No Device Intelligence findings stored.

#### Recommendations

- No recommendations stored.

---

### 192.168.233.135

#### Identity

- Hostname: Unknown
- MAC address: Unavailable
- Vendor: Unknown
- Classification: web_enabled_host
- Operating system: unknown
- Confidence: 35%
- Risk: low (15/100)
- First seen: 2026-08-03T18:04:32.880807-04:00
- Last seen: 2026-08-04T15:05:55.200895-04:00

#### Open Services

- 8080/tcp — http — SimpleHTTPServer 0.6 Python 3.13.14

#### Web Services

- http://192.168.233.135:8080/
- Status: 200 OK
  - Title: Cerberus Test Server
  - Server: SimpleHTTP/0.6 Python/3.13.14
  - Missing security headers: Content-Security-Policy, Permissions-Policy, Referrer-Policy, Strict-Transport-Security, X-Content-Type-Options, X-Frame-Options

#### Findings

- **LOW — Web security headers missing**
  - Evidence: Missing headers: Content-Security-Policy, Permissions-Policy, Referrer-Policy, Strict-Transport-Security, X-Content-Type-Options, X-Frame-Options
  - Recommendation: Review whether appropriate browser security headers can be enabled.
- **INFORMATIONAL — Web server banner disclosed**
  - Evidence: Server header: SimpleHTTP/0.6 Python/3.13.14
  - Recommendation: Consider reducing unnecessary version disclosure.

#### Recommendations

- Consider reducing unnecessary version disclosure.
- Review whether appropriate browser security headers can be enabled.

---

### 192.168.233.254

#### Identity

- Hostname: Unknown
- MAC address: Unavailable
- Vendor: Unknown
- Classification: unknown
- Operating system: unknown
- Confidence: 0%
- Risk: informational (0/100)
- First seen: 2026-08-03T18:04:32.880807-04:00
- Last seen: 2026-08-04T15:05:55.200895-04:00

#### Open Services

- No open services stored.

#### Web Services

- No web services stored.

#### Findings

- No Device Intelligence findings stored.

#### Recommendations

- No recommendations stored.

---


## Assessment Notes

- Observed facts originate from collected scan data.
- Device classifications and operating-system families may be inferred.
- Risk scores are Cerberus exposure assessments, not confirmed vulnerabilities.
- Findings should be manually validated before being treated as final conclusions.
