![Probe](probe.jpg)

# Probe

---

**Probe** is a modular security recon and vulnerability assessment framework designed for continuous web, network, and TLS analysis.

This repository contains the **public demonstration** of Probe. The full scanning engine and remainder of the project remains private.

---

## Features

### Public Current State (This Repository)

- Passive technology fingerprinting (server, framework, CDN, analytics, WAF)
- Network port enumeration and basic service identification
- TLS configuration and certificate inspection
- Security header analysis
- Sensitive file and misconfiguration detection
- CVE correlation using a local vulnerability database
- Safe GET-based checks for reflected XSS, SQL errors, path traversal, open redirects, command injection, template injection, and local file inclusion
- Optional same-origin browser checks for JavaScript-driven DOM XSS
- Explicit `safe-active` profile with bounded adaptive request budgets
- Grouped, severity-ordered findings with affected endpoint lists
- Automated attack-chain correlation
- Client-ready JSON, Markdown, HTML, and PDF output
- Transparent risk scoring per grouped finding

---

## Example Usage

```bash
python3 probe.py \
  https://example.com \
  --include fingerprinting,security_headers,network_scanner,tls_analysis
```

---

## Security Notice

Active checks use bounded, read-only GET requests and do not submit POST forms or follow external redirects.
DOM checks require the optional browser dependencies: `pip install -r requirements-dom.txt && playwright install chromium`.
Run scans only against systems you own or have explicit permission to test.

## License

MIT License — Public interface only.

Built as an independent security engineering project and portfolio project.
