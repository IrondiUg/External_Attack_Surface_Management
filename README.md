## External Attack Surface Management (EASM) Tool
> A Python-based External Attack Surface Management tool that discovers and assesses an organisation's external digital footprint in real time using open-source security scanners.

## Overview
Modern organisations continuously expand their external digital footprint through cloud adoption, third-party integrations, rapid deployments, shadow IT, forgotten infrastructure, temporary environments, and unmanaged internet-facing services.
Most security teams do not maintain complete visibility into these assets.
Attackers exploit that gap.
A single forgotten subdomain, exposed S3 bucket, abandoned staging server, leaked credential file, or misconfigured public service can become:
- an initial access vector,
- a ransomware entry point,
- a data breach source,
- a phishing infrastructure host,
- or a full-scale supply chain compromise.

This project was developed to `aggressively` identify those exposures before threat actors do.

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

**Project Structure**
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

### Python Dependencies
- `requests`
- `dnspython`
- `python-dotenv`

### External Security Tools
| Tool | Purpose | Source |
|---|---|---|
| Subfinder | Subdomain enumeration | [projectdiscovery/subfinder](https://github.com/projectdiscovery/subfinder) |
| Nuclei | Vulnerability scanning | [projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei) |


## Installation

### 1. Clone The Repository

```
git clone https://github.com/IrondiUg/External_Attack_Surface_Management.git
cd External_Attack_Surface_Management
```

2. Install Go on WSL
```
wget https://go.dev/dl/go1.22.3.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.22.3.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc
go version
```

3. Install Subfinder and Nuclei
```
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates
```

4. Create Python Virtual Environment
```
python3 -m venv venv
source venv/bin/activate
```
5. Install Python Dependencies
```
pip install requests dnspython python-dotenv
```

### Configuration
Create a .env file in the project root directory:
```
TARGET_DOMAIN=yourdomain.com
COMPANY_NAME=yourcompany
```

- `TARGET_DOMAIN` - Root domain of the target organisation
- `COMPANY_NAME` - Organisation name used for S3 permutation generation

### Run The Tool
```
source venv/bin/activate
python main.py
```

### Example Output
```
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
```

**Legal Notice**
⚠️ Important: This tool is intended strictly for use against systems and domains you own or have explicit written permission to test. Unauthorised scanning of systems you do not own may be illegal under applicable laws including the Computer Misuse Act and the Computer Fraud and Abuse Act. The author accepts no responsibility for any misuse of this tool.

---

**Author: Irondi Ugochukwu**

---

**References**
- Subfinder — https://github.com/projectdiscovery/subfinder
- Nuclei — https://github.com/projectdiscovery/nuclei
- dnspython — https://www.dnspython.org
- requests — https://docs.python-requests.org
- python-dotenv — https://pypi.org/project/python-dotenv
- AWS S3 Documentation — https://docs.aws.amazon.com/s3
