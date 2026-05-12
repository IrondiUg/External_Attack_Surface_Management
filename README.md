# External Attack Surface Management (EASM) Tool

> A Python-based External Attack Surface Management tool that discovers and assesses an organisation's external digital footprint in real time using open-source security scanners.

---

## Table of Contents
```
- [Overview](#overview)
- [Features](#features)
- [Project Structure](#project-structure)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [How It Works](#how-it-works)
- [Shadow IT Detection](#shadow-it-detection)
- [Limitations](#limitations)
- [Future Development](#future-development)
- [Legal Notice](#legal-notice)
- [Author](#author)
- [References](#references)
```
---

## Overview

This tool was developed as part of a cybersecurity project focused on external attack surface visibility. It enumerates subdomains, resolves DNS records, fingerprints HTTP services, detects exposed Amazon S3 buckets, and performs automated vulnerability assessments using the Nuclei scanner. All findings are displayed incrementally in real time via terminal output with no database or persistent storage layer required.

---

## Features

- **Subdomain Enumeration** — Passive discovery using Subfinder across multiple intelligence sources
- **DNS Resolution** — Validates discovered assets through A record and CNAME resolution
- **HTTP Fingerprinting** — Probes live services for status codes, page titles, and technology stacks
- **S3 Bucket Scanning** — Permutation-based detection of exposed Amazon S3 buckets
- **Vulnerability Assessment** — Automated scanning using Nuclei community templates
- **Shadow IT Detection** — Flags unknown assets not present in the approved asset baseline
- **Priority Scanning Queue** — Scans LIVE assets first, UNKNOWN second, DEAD last
- **Real-Time Output** — All findings printed line by line as scanning progresses

---

## Project Structure
```
easm-tool/
├── main.py                 # Central orchestrator
├── settings.py             # Configuration management
├── subdomain_scanner.py    # Subfinder-based subdomain enumeration
├── dns_resolver.py         # DNS resolution and validation
├── http_prober.py          # HTTP fingerprinting and technology detection
├── s3_scanner.py           # Amazon S3 bucket exposure scanner
├── nuclei_scanner.py       # Nuclei vulnerability scanner
├── .env                    # Environment variables (not committed)
├── .gitignore              # Git ignore rules
└── README.md               # Project documentation
```
---

## Requirements

### System Requirements

| Requirement | Version |
|---|---|
| Operating System | WSL Ubuntu 22.04 / Linux / macOS |
| Python | 3.8 or higher |
| Go | 1.22 or higher |

### Python Dependencies
requests
dnspython
python-dotenv
### External Security Tools

| Tool | Purpose | Source |
|---|---|---|
| Subfinder | Subdomain enumeration | [projectdiscovery/subfinder](https://github.com/projectdiscovery/subfinder) |
| Nuclei | Vulnerability scanning | [projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei) |

---

## Installation

### 1. Clone The Repository

```
git clone https://github.com/yourusername/easm-tool.git
cd easm-tool
```

2. Install Go
```wget https://go.dev/dl/go1.22.3.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.22.3.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc
go version
```

3. Install Subfinder and Nuclei
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates
4. Create Python Virtual Environment
python3 -m venv venv
source venv/bin/activate
5. Install Python Dependencies
pip install requests dnspython python-dotenv
Configuration
Create a .env file in the project root directory:
TARGET_DOMAIN=yourdomain.com
COMPANY_NAME=yourcompany
Variable
Description
Example
TARGET_DOMAIN
Root domain of the target organisation
example.com
COMPANY_NAME
Organisation name used for S3 permutation generation
example
⚠️ Warning: Never commit your .env file to version control. It is listed in .gitignore by default.
Usage
Run The Tool
source venv/bin/activate
python main.py
Example Output
=======================================================
  EASM Scan — example.com
=======================================================

=======================================================
  Phase 1a: Subdomain Discovery
=======================================================
[Subfinder] Scanning example.com...
[Subfinder] Found 5 unique subdomains

--- Discovered Subdomains ---
  [1] mail.example.com         (source: alienvault)
  [2] api.example.com          (source: virustotal)
  [3] dev.example.com          (source: subfinder)
  [4] staging.example.com      (source: certspotter)
  [5] vpn.example.com          (source: subfinder)

=======================================================
  Phase 1b: DNS Resolution
=======================================================
  [1/5] [OK]   mail.example.com    -> 93.184.216.34
  [2/5] [OK]   api.example.com     -> 93.184.216.35
  [3/5] [FAIL] dev.example.com     -> NXDOMAIN
  [4/5] [OK]   staging.example.com -> 93.184.216.36
  [5/5] [FAIL] vpn.example.com     -> TIMEOUT

=======================================================
  Phase 1c: HTTP Enrichment
=======================================================
  [1/3] mail.example.com    -> 200 | Mail Login        | Nginx
  [2/3] api.example.com     -> 403 | Forbidden         | Apache, Cloudflare
  [3/3] staging.example.com -> 200 | Staging Dashboard | Jenkins, React

=======================================================
  Phase 1d: S3 Bucket Scanning
=======================================================
[S3] Generated 38 bucket name permutations
  Checking [1/38]: example-dev     ... not found
  Checking [2/38]: example-backup  ... FOUND (public)
  Checking [3/38]: example-staging ... FOUND (private)

=======================================================
  Phase 1 Results — Full Summary
=======================================================

--- Subdomains ---
Domain                     IP              Status  Title              Tech
--------------------------------------------------------------------------
mail.example.com           93.184.216.34   200     Mail Login         Nginx
api.example.com            93.184.216.35   403     Forbidden          Apache
staging.example.com        93.184.216.36   200     Staging Dashboard  Jenkins
dev.example.com            -               -       -                  -
vpn.example.com            -               -       -                  -

--- S3 Bucket Findings ---
Bucket            Public  Listing  Severity  Files Found
--------------------------------------------------------
example-backup    YES     YES      CRITICAL  2 file(s)
  -> production.env
  -> db-dump-2024.sql
example-staging   No      No       MEDIUM    0 file(s)

=======================================================
  Phase 2: Vulnerability Scanning (Nuclei)
=======================================================

[Nuclei] Scanning LIVE subdomains (2 targets)...

  [FINDING]
  Name:        Jenkins Unauthenticated Dashboard
  Severity:    HIGH
  Host:        staging.example.com
  Matched URL: https://staging.example.com/dashboard
  Description: Jenkins dashboard accessible without authentication
  Tags:        jenkins, exposure, misconfig
  --------------------------------------------------

=======================================================
  Scan Complete
=======================================================
  Target:           example.com
  Subdomains found: 5
  Live domains:     2
  S3 buckets found: 2
  Public buckets:   1
  Nuclei findings:  1
    - Critical:     0
    - High:         1
    - Medium:       0
=======================================================
How It Works
Phase 1 — Asset Discovery
Phase 1a: Subdomain Enumeration
Subfinder queries multiple passive intelligence sources including certificate transparency logs, DNS aggregators, and threat intelligence platforms to discover subdomains associated with the target domain. Results are deduplicated and printed in real time as they are found.
Phase 1b: DNS Resolution
All discovered subdomains are resolved using dnspython. A record resolution is attempted first with CNAME fallback for domains without a direct IP mapping. Each domain is classified with a specific result:
Result
Meaning
OK
Domain resolved successfully
NXDOMAIN
Domain does not exist
NO_ANSWER
No DNS records found
TIMEOUT
Nameserver did not respond
Phase 1c: HTTP Fingerprinting
All DNS-resolved domains are probed over HTTPS with automatic HTTP fallback. SSL verification is disabled to capture misconfigured and self-signed endpoints. The following technologies are detected through signature-based analysis of response headers and body content:
WordPress Nginx Apache Cloudflare AWS S3 React Django Laravel Jenkins Grafana
Phase 1d: S3 Bucket Scanning
Bucket name permutations are generated by combining base names derived from the configured company name and target domain with thirty-four common suffix patterns. Each permutation is checked against AWS S3 endpoints and classified as follows:
HTTP Response
Classification
Severity
200
Publicly accessible
HIGH or CRITICAL
403
Exists but private
MEDIUM
301
Exists in another region
MEDIUM
404
Does not exist
—
Public buckets are further analysed for directory listing and sensitive file exposure. Files matching patterns such as .env, .sql, .pem, .key, and credential-related names elevate the finding to CRITICAL severity.
Phase 2 — Vulnerability Assessment
Discovered assets are classified into three priority scanning queues:
Queue
Criteria
LIVE
HTTP status 200, 301, 302, 401, 403
UNKNOWN
DNS resolved but no HTTP response
DEAD
DNS resolution failed
Nuclei scans each queue in priority order using its full community template library filtered to medium, high, and critical severity findings only. All discovered S3 bucket URLs are additionally scanned using Nuclei cloud-focused templates for deeper misconfiguration detection.
Shadow IT Detection
Any asset discovered during scanning that is not present in the organisation's known approved asset baseline is flagged as a Shadow IT candidate. These assets are assigned elevated priority during vulnerability scanning and represent potential security risks due to their unmonitored or unauthorised nature within the organisation's infrastructure.
Example scenario:
T+00m  Subfinder finds:  dev-api-test.example.com
T+01m  Not in approved baseline — flagged as Shadow IT
T+02m  HTTP probe finds:  exposed Jenkins dashboard
T+03m  Nuclei finds:     unauthenticated access (HIGH severity)
T+04m  Operator alerted — asset secured before exploitation
Limitations
GitHub repository leak scanning is not yet implemented
Dark web NLP sentiment analysis pipeline is not yet implemented
No persistent storage or historical trend analysis in current version
No automated scheduling for continuous scanning
No alerting system for critical findings via Slack, email, or webhook
No visualisation dashboard for scan results
Amass not included in current version — Subfinder used exclusively
Future Development
GitHub Scanning — Repository leak detection using the GitHub Search API and gitleaks
NLP Intelligence — Dark web sentiment analysis using HuggingFace Transformers and SecBERT
Automated Scheduling — Continuous monitoring using APScheduler
Dashboard — Real-time visualisation using Flask and Chart.js
Alerting — Critical finding notifications via Slack, email, and webhook
OWASP ZAP — Deeper web application assessment for high-value targets
Persistent Storage — SQLite or PostgreSQL backend for historical trend analysis
Legal Notice
⚠️ Important: This tool is intended strictly for use against systems and domains you own or have explicit written permission to test. Unauthorised scanning of systems you do not own may be illegal under applicable laws including the Computer Misuse Act and the Computer Fraud and Abuse Act. The author accepts no responsibility for any misuse of this tool.
Author
Irondi Ugochukwu
References
Subfinder — https://github.com/projectdiscovery/subfinder
Nuclei — https://github.com/projectdiscovery/nuclei
dnspython — https://www.dnspython.org
requests — https://docs.python-requests.org
python-dotenv — https://pypi.org/project/python-dotenv
AWS S3 Documentation — https://docs.aws.amazon.com/s3
