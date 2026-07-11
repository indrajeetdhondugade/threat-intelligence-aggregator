# 🛡️ Threat Intelligence Aggregator (Non-AI)

**A Python-based Blue Team / SOC toolkit that automates the full threat intelligence pipeline from raw feed ingestion to deployment-ready blocklists and reports. ****

![Python](https://img.shields.io/badge/Python-3.14-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Complete-brightgreen)


## 📋 Overview

Security Operations Centres (SOCs) receive Indicators of Compromise (IOCs) from dozens of sources daily in inconsistent formats, with duplicates, and with no built-in way to prioritise what actually matters. This project solves that problem with a fully automated, rule-based Python pipeline.

Given raw IOC feeds in **TXT, CSV, and JSON** formats, the tool:
- Extracts and validates 5 IOC types (IP, domain, URL, hash, email)
- Correlates indicators across multiple feeds
- Calculates a transparent, explainable **0–100 risk score** for each one
- Generates **21 deployment-ready blocklist files** across 7 categories
- Produces a professional **TXT / JSON / HTML** threat intelligence report including a self-contained SOC dashboard

**Runtime:** 0.07 seconds for a full 4-feed, 30-IOC pipeline run.
## ✨ Features

### Feed Processing
- Automatic format detection TXT, CSV, JSON
- Comment and empty-line filtering
- Handles messy real-world data (private IPs, duplicates, junk entries) without crashing

### IOC Extraction & Validation
- Regex-based extraction for 5 IOC types: IP, Domain, URL, File Hash, Email
- Rejects private/reserved/loopback IP ranges automatically
- Hash length validation (MD5 / SHA1 / SHA256)
- URL cleaning (strips trailing punctuation)

### Correlation & Risk Scoring
- Cross-feed correlation tracks which sources reported each IOC
- Transparent 3-factor scoring formula (0–100): source frequency + IOC type weight + keyword severity
- Score labels: LOW / MEDIUM / HIGH / CRITICAL
- ## 🛠️ Tech Stack

**Language:** Python 3.14

### Why Standard Library Only?
No frameworks. No paid APIs. No pip install for core functionality. This runs on any machine with Python 3 — nothing else to configure.

| Module | Used For |
| `re` | Regex-based extraction of all 5 IOC types |
| `ipaddress` | Rejecting private, loopback & reserved IP ranges |
| `json` | Parsing JSON feeds & exporting structured reports |
| `csv` | Reading/writing structured feed data |
| `collections.defaultdict` | Cross-feed correlation & IOC grouping |
| `datetime` | Timestamping every IOC and output file |
| `time` | Measuring pipeline runtime (0.07s) |
| `os` | Directory scanning & cross-platform path handling |

### One External Dependency
`requests` is installed and ready, but not yet active. Reserved for a v2.0 feature: live feed fetching from OSINT APIs like AlienVault OTX and AbuseIPDB.

### Development Environment
`VS Code 1.124` · `PowerShell` · `Windows 11`

> 💡 **Design philosophy:** Every dependency was a deliberate choice, not a default. If Python's standard library could do it, that's what got used.

### Output Generation
- **21 blocklist files** — 7 categories × 3 formats (TXT/CSV/JSON), ready for firewalls, DNS filters, web proxies, EDR/AV, and email gateways
- **3 report formats** — human-readable TXT, machine-readable JSON, and a self-contained HTML SOC dashboard

## 📁 Project Structure

    threat-intelligence-aggregator/
    │
    ├── feeds/                      # Input IOC feeds
    │   ├── feed1.txt                # Plain text feed
    │   ├── feed2.csv                # Structured CSV feed
    │   ├── feed3.json               # JSON-formatted feed
    │   └── feed4.txt                # Edge-case testing feed
    │
    ├── modules/                    # Core pipeline modules
    │   ├── __init__.py
    │   ├── feed_loader.py           # Step 1 — Load & detect feed format
    │   ├── ioc_parser.py            # Step 2 — Extract & validate IOCs
    │   ├── normalizer.py            # Step 3 — Enrich with metadata
    │   ├── correlator.py            # Step 4 — Correlate & score risk
    │   ├── blocklist_gen.py         # Step 5 — Generate 21 blocklists
    │   └── reporter.py              # Step 6 — Generate TXT/JSON/HTML reports
    │
    ├── output/                     # Generated on each run (not committed)
    │   ├── blocklists/               # 21 files across 7 categories
    │   └── reports/                  # TXT, JSON, HTML dashboard
    │
    ├── main.py                      # Pipeline entry point
    ├── .gitignore
    ├── LICENSE
    └── README.md

**Pipeline flow:** `main.py` → `feed_loader` → `ioc_parser` → `normalizer` → `correlator` → `blocklist_gen` + `reporter`
## 🚀 How to Run

### Prerequisites
- Python 3.10 or higher installed ([python.org/downloads](https://www.python.org/downloads/))
- No other installations needed — this project only uses Python's standard library

### 1. Clone the repository
```bash
git clone https://github.com/indrajeetdhondugade/threat-intelligence-aggregator.git
cd threat-intelligence-aggregator
```

### 2. Run the pipeline
```bash
python main.py
```

That's it, no `pip install` required for core functionality. The `feeds/` folder already contains sample IOC feeds (TXT, CSV, JSON) so the pipeline runs out of the box.

### 3. Check the results
After running, a new `output/` folder is created (not committed to the repo) containing:
- `output/blocklists/` 21 blocklist files across 7 categories, in TXT/CSV/JSON
- `output/reports/` a TXT report, a JSON report, and a self-contained HTML SOC dashboard

Open `output/reports/*.html` in any browser to view the dashboard.

### 4. Use your own feeds
Drop your own IOC feed files (`.txt`, `.csv`, or `.json`) into the `feeds/` folder and re-run `python main.py` — format detection is automatic.

## 📊 Sample Output

Running `python main.py` on the included sample feeds produces results like this:

### Console Summary
```
Loading feeds...
  ✓ feed1.txt   (TXT)
  ✓ feed2.csv   (CSV)
  ✓ feed3.json  (JSON)
  ✓ feed4.txt   (TXT)

Parsing IOCs...        30 IOCs extracted
Correlating...          15 correlations found
Risk scoring...         6 CRITICAL | rest scored LOW–HIGH
Generating blocklists... 21 files across 7 categories
Generating reports...    TXT, JSON, HTML dashboard

Done in 0.07s
```

### Reports Generated
| Output | Location | Format |
|---|---|---|
| Text report | `output/reports/report.txt` | Plain text summary |
| JSON report | `output/reports/report.json` | Machine-readable, for integration into other tools |
| HTML dashboard | `output/reports/dashboard.html` | Visual SOC-style dashboard — open in any browser |

### Blocklists Generated
21 blocklist files are generated across 7 categories (e.g. malicious IPs, phishing domains, malware hashes), in TXT/CSV/JSON so they can be dropped straight into a firewall, SIEM, or other blocklist-consuming tool.

> Screenshot of the HTML dashboard: 
<img width="1919" height="914" alt="Day15_html_dashboard_top 1" src="https://github.com/user-attachments/assets/014e2228-9172-4ce5-87f8-d816e65504cc" />
