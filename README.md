<div align="center">

```
  ____           _                      _
 |  _ \ ___ _ __(_)_ __ ___   ___  _ __| |
 | |_) / _ \ '__| | '_ ` _ \ / _ \| '__| |
 |  __/  __/ |  | | | | | | |  __/| |  |_|
 |_|   \___|_|  |_|_| |_| |_|\___||_|  (_)
  _____            _
 | ____|_  ___ __ | | ___  _ __ ___ _ __
 |  _| \ \/ / '_ \| |/ _ \| '__/ _ \ '__|
 | |___ >  <| |_) | | (_) | | |  __/ |
 |_____/_/\_\ .__/|_|\___/|_|  \___|_|
            |_|
```

**Automated Subdomain Enumeration & Attack Surface Mapping**

![Version](https://img.shields.io/badge/version-1.1.0-brightgreen?style=flat-square)
![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)
![License](https://img.shields.io/github/license/DigitalOhara/PerimeterExplorer?style=flat-square)
![Stars](https://img.shields.io/github/stars/DigitalOhara/PerimeterExplorer?style=flat-square)
![Last Commit](https://img.shields.io/github/last-commit/DigitalOhara/PerimeterExplorer?style=flat-square)

</div>

---

## Overview

**PerimeterExplorer** is a Python-based subdomain enumeration framework that aggregates results from multiple industry-standard tools and public APIs into a single, unified workflow. Instead of running each tool individually and merging results by hand, PerimeterExplorer orchestrates the entire passive and active reconnaissance pipeline, deduplicates every finding, and delivers clean output in **TXT**, **CSV**, and **HTML** formats — all named automatically with the target domain and a timestamp.

Designed for penetration testers, bug bounty hunters, and red teamers who need fast, comprehensive subdomain coverage without the manual overhead.

---

## Features

- **19 enumeration sources** — passive APIs, threat intelligence, certificate transparency, active DNS brute-force, and more
- **Automatic deduplication** — all sources are merged and deduplicated into a single result set
- **Three output formats** — `.txt` (raw list), `.csv` (with source attribution), `.html` (interactive dark-themed report)
- **Timestamped output** — files are named `domain_YYYYMMDD_HHMMSS.*` for easy archiving
- **Bulk mode** — scan a single domain or feed a file containing hundreds of targets
- **Graceful degradation** — tools not installed are skipped with a warning; the scan continues
- **Optional API keys** — VirusTotal, SecurityTrails, and Shodan keys unlock deeper results but are never required
- **`--skip-active` flag** — passive-only mode for stealth engagements or rate-limited environments

---

## Enumeration Sources

| Source | Type | Key Required | Method |
|---|---|---|---|
| [subfinder](https://github.com/projectdiscovery/subfinder) | Passive | No | External binary |
| [assetfinder](https://github.com/tomnomnom/assetfinder) | Passive | No | External binary |
| [findomain](https://github.com/Findomain/Findomain) | Passive | No | External binary |
| [amass](https://github.com/owasp-amass/amass) *(passive)* | Passive | No | External binary |
| [amass](https://github.com/owasp-amass/amass) *(active)* | Active | No | External binary |
| [crt.sh](https://crt.sh) | Passive | No | Certificate Transparency API |
| [CertSpotter](https://sslmate.com/certspotter) | Passive | No | Certificate Transparency API |
| [Wayback Machine](https://web.archive.org) | Passive | No | CDX API |
| [VirusTotal](https://www.virustotal.com) | Passive | Optional (`--vt-key`) | Public UI / API v3 |
| [HackerTarget](https://hackertarget.com) | Passive | No | Host Search API |
| [AlienVault OTX](https://otx.alienvault.com) | Passive | No | Passive DNS API |
| [RapidDNS](https://rapiddns.io) | Passive | No | Subdomain lookup |
| [ThreatMiner](https://www.threatminer.org) | Passive | No | Domain API |
| [Anubis-DB](https://jldc.me/anubis) | Passive | No | Subdomain DB API |
| [URLScan.io](https://urlscan.io) | Passive | No | Domain search API |
| [SecurityTrails](https://securitytrails.com) | Passive | Optional (`--st-key`) | Subdomain history API |
| [Shodan](https://www.shodan.io) | Passive | Optional (`--shodan-key`) | DNS domain API |
| [dnsrecon](https://github.com/darkoperator/dnsrecon) | Active | No | External binary / pip |
| [fierce](https://github.com/mschwager/fierce) | Active | No | External binary / pip |

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/DigitalOhara/PerimeterExplorer.git
cd PerimeterExplorer
```

### 2. Install Python dependencies

```bash
pip install -r requirements.txt
```

### 3. Install external tools

PerimeterExplorer calls external binaries. Install the ones you need:

```bash
# subfinder (requires Go)
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# assetfinder (requires Go)
go install github.com/tomnomnom/assetfinder@latest

# findomain — grab the latest binary from the releases page
# https://github.com/Findomain/Findomain/releases

# amass (requires Go)
go install -v github.com/owasp-amass/amass/v4/...@master

# dnsrecon & fierce (pip)
pip install dnsrecon fierce
```

> Tools that are not installed are **skipped automatically** — the scan will still run with whatever is available.

---

## Usage

```
python perimeterexplorer.py [-h] (-d DOMAIN | -f FILE)
                            [-o OUTPUT]
                            [--vt-key VT_KEY]
                            [--st-key ST_KEY]
                            [--shodan-key SHODAN_KEY]
                            [--wordlist WORDLIST]
                            [--skip-active]
                            [--skip-install]
```

### Options

| Flag | Description |
|---|---|
| `-d DOMAIN` | Single target domain |
| `-f FILE` | File containing one domain per line |
| `-o OUTPUT` | Base output directory (default: `./results`) |
| `--vt-key KEY` | VirusTotal API v3 key for paginated results |
| `--st-key KEY` | SecurityTrails API key for historical subdomain data |
| `--shodan-key KEY` | Shodan API key for reverse-PTR DNS records |
| `--wordlist PATH` | Wordlist for fierce DNS brute-force |
| `--skip-active` | Skip active recon (amass active, fierce, dnsrecon) |
| `--skip-install` | Skip automatic tool installation check at startup |

### Examples

```bash
# Scan a single domain
python perimeterexplorer.py -d example.com

# Scan a list of domains from a file
python perimeterexplorer.py -f targets.txt

# Passive-only scan (no active DNS brute-force)
python perimeterexplorer.py -d example.com --skip-active

# Full scan with all optional API keys
python perimeterexplorer.py -d example.com \
    --vt-key YOUR_VT_KEY \
    --st-key YOUR_ST_KEY \
    --shodan-key YOUR_SHODAN_KEY

# Full scan with custom wordlist for fierce
python perimeterexplorer.py -d example.com \
    --wordlist /usr/share/wordlists/subdomains.txt \
    --vt-key YOUR_VT_KEY
```

---

## Output

Each scan creates a timestamped directory under `results/`:

```
results/
└── example.com_20260320_143022/
    ├── subfinder.txt
    ├── assetfinder.txt
    ├── findomain.txt
    ├── amass.txt
    ├── amass_active.txt
    ├── crtsh.txt
    ├── certspotter.txt
    ├── wayback.txt
    ├── virustotal.txt
    ├── hackertarget.txt
    ├── alienvault.txt
    ├── rapiddns.txt
    ├── threatminer.txt
    ├── anubis.txt
    ├── urlscan.txt
    ├── dnsrecon.xml
    ├── fierce.txt
    ├── example.com_20260320_143022.txt   # Combined deduplicated list
    ├── example.com_20260320_143022.csv   # With source attribution
    └── example.com_20260320_143022.html  # Interactive HTML report
```

### HTML Report

The HTML report is a self-contained, dark-themed page that includes:

- Total subdomain count and sources used
- Per-tool breakdown table
- Full subdomain table with source tags and a **live search/filter box**

---

## Changelog

### v1.1.0 — 2026-07-17
- **Added 8 new passive DNS sources:** HackerTarget, AlienVault OTX, RapidDNS, ThreatMiner, Anubis-DB, URLScan.io, CertSpotter (all free, no API key required)
- **Added SecurityTrails integration** (`--st-key`) for historical subdomain enumeration
- **Added Shodan DNS integration** (`--shodan-key`) for reverse-PTR records from IP range scanning
- **Fixed** `IndentationError` in `run_virustotal` and `_vt_request` methods that prevented the tool from running

### v1.0.0 — Initial Release
- Subdomain enumeration via subfinder, assetfinder, findomain, amass, crt.sh, Wayback Machine, VirusTotal, dnsrecon, fierce
- TXT, CSV, and HTML output formats
- Bulk domain scanning via `-f` flag
- Automatic tool installation at startup

---

## Disclaimer

> This tool is intended for **authorized security assessments, penetration testing engagements, and bug bounty programs only**. Always ensure you have explicit written permission before scanning any target. The author is not responsible for any misuse or damage caused by this tool. Use responsibly and in accordance with all applicable laws.

---

## License

Distributed under the MIT License. See [`LICENSE`](LICENSE) for details.

---

<div align="center">
Made by <a href="https://github.com/DigitalOhara">DigitalOhara</a>
</div>
