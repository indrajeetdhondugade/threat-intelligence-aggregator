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

**Runtime:** 0.07 seconds for a full 4-feed, 30-IOC pipeline run.# threat-intelligence-aggregator
A Python-based Blue Team toolkit that automates threat intelligence feed aggregation, correlation, risk scoring, and blocklist generation
Update README
