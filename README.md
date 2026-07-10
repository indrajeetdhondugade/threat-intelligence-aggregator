# 🛡️ Threat Intelligence Aggregator (Non-AI)

**A Python-based Blue Team / SOC toolkit that automates the full threat intelligence pipeline — from raw feed ingestion to deployment-ready blocklists and reports.**

![Python](https://img.shields.io/badge/Python-3.14-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Complete-brightgreen)

---

## 📋 Overview

Security Operations Centres (SOCs) receive Indicators of Compromise (IOCs) from dozens of sources daily — in inconsistent formats, with duplicates, and with no built-in way to prioritise what actually matters. This project solves that problem with a fully automated, rule-based Python pipeline.

Given raw IOC feeds in **TXT, CSV, and JSON** formats, the tool:
- Extracts and validates 5 IOC types (IP, domain, URL, hash, email)
- Correlates indicators across multiple feeds
- Calculates a transparent, explainable **0–100 risk score** for each one
- Generates **21 deployment-ready blocklist files** across 7 categories
- Produces a professional **TXT / JSON / HTML** threat intelligence report — including a self-contained SOC dashboard

**Runtime:** 0.07 seconds for a full 4-feed, 30-IOC pipeline run.
## ✨ Features

### Feed Processing
- Automatic format detection — TXT, CSV, JSON
- Comment and empty-line filtering
- Handles messy real-world data (private IPs, duplicates, junk entries) without crashing

### IOC Extraction & Validation
- Regex-based extraction for 5 IOC types: IP, Domain, URL, File Hash, Email
- Rejects private/reserved/loopback IP ranges automatically
- Hash length validation (MD5 / SHA1 / SHA256)
- URL cleaning (strips trailing punctuation)

### Correlation & Risk Scoring
- Cross-feed correlation — tracks which sources reported each IOC
- Transparent 3-factor scoring formula (0–100): source frequency + IOC type weight + keyword severity
- Score labels: LOW / MEDIUM / HIGH / CRITICAL

### Output Generation
- **21 blocklist files** — 7 categories × 3 formats (TXT/CSV/JSON), ready for firewalls, DNS filters, web proxies, EDR/AV, and email gateways
- **3 report formats** — human-readable TXT, machine-readable JSON, and a self-contained HTML SOC dashboard
- Dashboard includes risk distribution charts, critical IOC alerts, and a full ranked IOC table
-  Update README
