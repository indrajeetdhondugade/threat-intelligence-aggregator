# reporter.py — Generates a full Threat Intelligence Report

import os
import json
from datetime import datetime

OUTPUT_DIR = "output/reports"


def generate_report(feeds, iocs, normalized_iocs,
                    correlated_iocs, blocklist_data):
    """
    Generate a complete TI report in TXT and JSON formats.
    """
    print("\n[*] Generating Threat Intelligence Report...")

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    timestamp   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report_date = datetime.now().strftime("%Y-%m-%d")

    # Build report data
    report = _build_report(
        feeds, iocs, normalized_iocs,
        correlated_iocs, blocklist_data,
        timestamp
    )

    # Export TXT report
    txt_filename = f"threat_report_{report_date}.txt"
    _write_txt_report(report, txt_filename)

    # Export JSON report
    json_filename = f"threat_report_{report_date}.json"
    _write_json_report(report, json_filename)

    print(f"\n[+] Reports saved to: {OUTPUT_DIR}/")
    print(f"    {txt_filename}")
    print(f"    {json_filename}")

    return report


def _build_report(feeds, iocs, normalized_iocs,
                  correlated_iocs, blocklist_data, timestamp):
    """Build the full report data structure."""

    # IOC type counts
    type_counts = {}
    for t in ["ip", "domain", "url", "hash", "email"]:
        type_counts[t] = sum(
            1 for i in correlated_iocs if i["type"] == t
        )

    # Score label counts
    score_counts = {}
    for label in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        score_counts[label] = sum(
            1 for i in correlated_iocs
            if i["score_label"] == label
        )

    # Top 10 highest risk IOCs
    top_iocs = sorted(
        correlated_iocs,
        key=lambda x: x["risk_score"],
        reverse=True
    )[:10]

    # Critical IOCs only
    critical_iocs = [
        i for i in correlated_iocs
        if i["score_label"] == "CRITICAL"
    ]

    # Feed summary
    feed_summary = []
    for feed in feeds:
        feed_summary.append({
            "source" : feed["source"],
            "format" : feed["format"],
            "entries": len(feed["raw_lines"])
        })

    return {
        "metadata": {
            "title"    : "Threat Intelligence Report",
            "tool"     : "Threat Intelligence Aggregator (Non-AI)",
            "generated": timestamp,
            "version"  : "1.0"
        },
        "summary": {
            "total_feeds"      : len(feeds),
            "total_iocs_parsed": len(iocs),
            "total_normalized" : len(normalized_iocs),
            "total_correlated" : len(correlated_iocs),
            "critical_iocs"    : score_counts.get("CRITICAL", 0),
            "high_iocs"        : score_counts.get("HIGH", 0),
            "medium_iocs"      : score_counts.get("MEDIUM", 0),
            "low_iocs"         : score_counts.get("LOW", 0)
        },
        "feed_summary"  : feed_summary,
        "type_counts"   : type_counts,
        "score_counts"  : score_counts,
        "top_iocs"      : top_iocs,
        "critical_iocs" : critical_iocs,
        "blocklist_summary": {
            "ips"          : len(blocklist_data.get("ips", [])),
            "domains"      : len(blocklist_data.get("domains", [])),
            "urls"         : len(blocklist_data.get("urls", [])),
            "hashes"       : len(blocklist_data.get("hashes", [])),
            "emails"       : len(blocklist_data.get("emails", [])),
            "high_priority": len(blocklist_data.get("high_priority", []))
        }
    }


def _write_txt_report(report, filename):
    """Write a human-readable TXT threat report."""
    filepath = os.path.join(OUTPUT_DIR, filename)

    with open(filepath, "w") as f:

        # Header
        f.write("=" * 60 + "\n")
        f.write("   THREAT INTELLIGENCE REPORT\n")
        f.write("=" * 60 + "\n")
        f.write(f"   Tool      : {report['metadata']['tool']}\n")
        f.write(f"   Generated : {report['metadata']['generated']}\n")
        f.write(f"   Version   : {report['metadata']['version']}\n")
        f.write("=" * 60 + "\n\n")

        # Executive Summary
        f.write("[ EXECUTIVE SUMMARY ]\n")
        f.write("-" * 40 + "\n")
        s = report["summary"]
        f.write(f"  Total feeds processed  : {s['total_feeds']}\n")
        f.write(f"  Total IOCs parsed      : {s['total_iocs_parsed']}\n")
        f.write(f"  Total IOCs normalized  : {s['total_normalized']}\n")
        f.write(f"  Total IOCs correlated  : {s['total_correlated']}\n")
        f.write(f"\n  CRITICAL IOCs          : {s['critical_iocs']}\n")
        f.write(f"  HIGH IOCs              : {s['high_iocs']}\n")
        f.write(f"  MEDIUM IOCs            : {s['medium_iocs']}\n")
        f.write(f"  LOW IOCs               : {s['low_iocs']}\n")
        f.write("\n")

        # Feed Summary
        f.write("[ FEED SUMMARY ]\n")
        f.write("-" * 40 + "\n")
        for feed in report["feed_summary"]:
            f.write(
                f"  {feed['source']:<25} "
                f"format: {feed['format']:<6} "
                f"entries: {feed['entries']}\n"
            )
        f.write("\n")

        # IOC Type Breakdown
        f.write("[ IOC TYPE BREAKDOWN ]\n")
        f.write("-" * 40 + "\n")
        for ioc_type, count in report["type_counts"].items():
            f.write(f"  {ioc_type.upper():<12}: {count}\n")
        f.write("\n")

        # Score Distribution
        f.write("[ RISK SCORE DISTRIBUTION ]\n")
        f.write("-" * 40 + "\n")
        for label, count in report["score_counts"].items():
            bar = "#" * count
            f.write(f"  {label:<10}: {count:>3}  {bar}\n")
        f.write("\n")

        # Critical IOCs
        f.write("[ CRITICAL IOCs — IMMEDIATE ACTION REQUIRED ]\n")
        f.write("-" * 40 + "\n")
        if report["critical_iocs"]:
            for ioc in report["critical_iocs"]:
                feeds_str = ", ".join(ioc["feeds"])
                f.write(f"  [!] {ioc['value']}\n")
                f.write(f"      Type   : {ioc['type']}\n")
                f.write(f"      Score  : {ioc['risk_score']}\n")
                f.write(f"      Feeds  : {feeds_str}\n")
                f.write("\n")
        else:
            f.write("  No critical IOCs found.\n\n")

        # Top 10 IOCs
        f.write("[ TOP 10 HIGHEST RISK IOCs ]\n")
        f.write("-" * 40 + "\n")
        f.write(
            f"  {'#':<4} {'SCORE':<7} {'LABEL':<10} "
            f"{'TYPE':<10} {'VALUE'}\n"
        )
        f.write("  " + "-" * 55 + "\n")
        for idx, ioc in enumerate(report["top_iocs"], 1):
            f.write(
                f"  {idx:<4} {ioc['risk_score']:<7} "
                f"{ioc['score_label']:<10} "
                f"{ioc['type']:<10} {ioc['value']}\n"
            )
        f.write("\n")

        # Blocklist Summary
        f.write("[ BLOCKLIST SUMMARY ]\n")
        f.write("-" * 40 + "\n")
        bl = report["blocklist_summary"]
        f.write(f"  IP blocklist      : {bl['ips']} entries\n")
        f.write(f"  Domain blocklist  : {bl['domains']} entries\n")
        f.write(f"  URL blocklist     : {bl['urls']} entries\n")
        f.write(f"  Hash blocklist    : {bl['hashes']} entries\n")
        f.write(f"  Email blocklist   : {bl['emails']} entries\n")
        f.write(f"  High priority     : {bl['high_priority']} entries\n")
        f.write("\n")

        # Footer
        f.write("=" * 60 + "\n")
        f.write("  END OF REPORT\n")
        f.write("=" * 60 + "\n")

    print(f"    [+] TXT report saved: {filename}")


def _write_json_report(report, filename):
    """Write a machine-readable JSON threat report."""
    filepath = os.path.join(OUTPUT_DIR, filename)
    with open(filepath, "w") as f:
        json.dump(report, f, indent=4)
    print(f"    [+] JSON report saved: {filename}")

    def generate_html_report(report):
         print("\n[*] Generating HTML Dashboard...")

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    report_date = datetime.now().strftime("%Y-%m-%d")
    filename    = f"threat_report_{report_date}.html"
    filepath    = os.path.join(OUTPUT_DIR, filename)

    # Build IOC table rows
    ioc_rows = ""
    for ioc in report["top_iocs"]:
        feeds_str   = ", ".join(ioc["feeds"])
        label       = ioc["score_label"]
        score       = ioc["risk_score"]

        if label == "CRITICAL":
            badge = f'<span class="badge critical">{label}</span>'
        elif label == "HIGH":
            badge = f'<span class="badge high">{label}</span>'
        elif label == "MEDIUM":
            badge = f'<span class="badge medium">{label}</span>'
        else:
            badge = f'<span class="badge low">{label}</span>'

        ioc_rows += f"""
        <tr>
            <td>{score}</td>
            <td>{badge}</td>
            <td><span class="type-tag">{ioc['type']}</span></td>
            <td class="ioc-value">{ioc['value']}</td>
            <td>{ioc['feed_count']}</td>
            <td class="feeds-cell">{feeds_str}</td>
        </tr>"""

    # Build feed rows
    feed_rows = ""
    for feed in report["feed_summary"]:
        feed_rows += f"""
        <tr>
            <td>{feed['source']}</td>
            <td><span class="type-tag">{feed['format']}</span></td>
            <td>{feed['entries']}</td>
        </tr>"""

    # Build critical IOC cards
    critical_cards = ""
    for ioc in report["critical_iocs"]:
        feeds_str = ", ".join(ioc["feeds"])
        critical_cards += f"""
        <div class="critical-card">
            <div class="critical-header">
                <span class="alert-icon">!</span>
                <span class="critical-value">{ioc['value']}</span>
            </div>
            <div class="critical-details">
                <span>Type: {ioc['type']}</span>
                <span>Score: {ioc['risk_score']}</span>
                <span>Feeds: {feeds_str}</span>
            </div>
        </div>"""

    if not critical_cards:
        critical_cards = "<p style='color:#666'>No critical IOCs found.</p>"

    # Summary data
    s  = report["summary"]
    bl = report["blocklist_summary"]
    tc = report["type_counts"]
    sc = report["score_counts"]

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Threat Intelligence Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', sans-serif;
            background: #0d1117;
            color: #c9d1d9;
            padding: 20px;
        }}
        .header {{
            background: linear-gradient(135deg, #1a1f2e, #2d1b69);
            border: 1px solid #30363d;
            border-radius: 12px;
            padding: 30px;
            margin-bottom: 24px;
            text-align: center;
        }}
        .header h1 {{
            font-size: 28px;
            color: #58a6ff;
            margin-bottom: 8px;
        }}
        .header p {{
            color: #8b949e;
            font-size: 14px;
        }}
        .header .subtitle {{
            color: #3fb950;
            font-size: 13px;
            margin-top: 6px;
        }}
        .cards-grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 16px;
            margin-bottom: 24px;
        }}
        .card {{
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 10px;
            padding: 20px;
            text-align: center;
        }}
        .card .card-value {{
            font-size: 36px;
            font-weight: bold;
            margin-bottom: 6px;
        }}
        .card .card-label {{
            font-size: 12px;
            color: #8b949e;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        .card.blue   .card-value {{ color: #58a6ff; }}
        .card.green  .card-value {{ color: #3fb950; }}
        .card.red    .card-value {{ color: #f85149; }}
        .card.orange .card-value {{ color: #e3b341; }}
        .section {{
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 10px;
            padding: 24px;
            margin-bottom: 24px;
        }}
        .section h2 {{
            font-size: 16px;
            color: #58a6ff;
            margin-bottom: 16px;
            padding-bottom: 10px;
            border-bottom: 1px solid #30363d;
        }}
        .two-col {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 16px;
            margin-bottom: 24px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }}
        th {{
            background: #0d1117;
            color: #8b949e;
            padding: 10px 12px;
            text-align: left;
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 1px;
            border-bottom: 1px solid #30363d;
        }}
        td {{
            padding: 10px 12px;
            border-bottom: 1px solid #21262d;
            vertical-align: middle;
        }}
        tr:hover td {{ background: #1c2128; }}
        .badge {{
            padding: 3px 10px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: bold;
        }}
        .badge.critical {{
            background: #3d0000;
            color: #f85149;
            border: 1px solid #f85149;
        }}
        .badge.high {{
            background: #2d1a00;
            color: #e3b341;
            border: 1px solid #e3b341;
        }}
        .badge.medium {{
            background: #0d2818;
            color: #3fb950;
            border: 1px solid #3fb950;
        }}
        .badge.low {{
            background: #1a1f2e;
            color: #58a6ff;
            border: 1px solid #58a6ff;
        }}
        .type-tag {{
            background: #21262d;
            color: #8b949e;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-family: monospace;
        }}
        .ioc-value {{
            font-family: monospace;
            color: #79c0ff;
            font-size: 12px;
        }}
        .feeds-cell {{
            font-size: 11px;
            color: #8b949e;
        }}
        .risk-bar-wrap {{
            margin-bottom: 14px;
        }}
        .risk-bar-label {{
            display: flex;
            justify-content: space-between;
            margin-bottom: 5px;
            font-size: 13px;
        }}
        .risk-bar-track {{
            background: #21262d;
            border-radius: 4px;
            height: 10px;
            overflow: hidden;
        }}
        .risk-bar-fill {{
            height: 100%;
            border-radius: 4px;
            transition: width 0.3s;
        }}
        .fill-critical {{ background: #f85149; }}
        .fill-high     {{ background: #e3b341; }}
        .fill-medium   {{ background: #3fb950; }}
        .fill-low      {{ background: #58a6ff; }}
        .critical-card {{
            background: #1a0a0a;
            border: 1px solid #f85149;
            border-left: 4px solid #f85149;
            border-radius: 8px;
            padding: 14px 16px;
            margin-bottom: 12px;
        }}
        .critical-header {{
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 8px;
        }}
        .alert-icon {{
            background: #f85149;
            color: white;
            width: 22px;
            height: 22px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: bold;
            font-size: 13px;
            flex-shrink: 0;
        }}
        .critical-value {{
            font-family: monospace;
            color: #f85149;
            font-size: 14px;
            font-weight: bold;
        }}
        .critical-details {{
            display: flex;
            gap: 20px;
            font-size: 12px;
            color: #8b949e;
            margin-left: 32px;
        }}
        .stat-row {{
            display: flex;
            justify-content: space-between;
            padding: 8px 0;
            border-bottom: 1px solid #21262d;
            font-size: 13px;
        }}
        .stat-row:last-child {{ border-bottom: none; }}
        .stat-label {{ color: #8b949e; }}
        .stat-value {{ color: #c9d1d9; font-weight: 500; }}
        .footer {{
            text-align: center;
            color: #8b949e;
            font-size: 12px;
            padding: 20px;
            border-top: 1px solid #30363d;
            margin-top: 24px;
        }}
    </style>
</head>
<body>

<!-- Header -->
<div class="header">
    <h1>Threat Intelligence Report</h1>
    <p>Generated: {report['metadata']['generated']}</p>
    <p class="subtitle">Threat Intelligence Aggregator (Non-AI) v1.0</p>
</div>

<!-- Summary Cards -->
<div class="cards-grid">
    <div class="card blue">
        <div class="card-value">{s['total_feeds']}</div>
        <div class="card-label">Feeds Processed</div>
    </div>
    <div class="card green">
        <div class="card-value">{s['total_correlated']}</div>
        <div class="card-label">IOCs Correlated</div>
    </div>
    <div class="card red">
        <div class="card-value">{s['critical_iocs']}</div>
        <div class="card-label">Critical IOCs</div>
    </div>
    <div class="card orange">
        <div class="card-value">{s['high_iocs']}</div>
        <div class="card-label">High IOCs</div>
    </div>
</div>

<!-- Risk Distribution + IOC Types -->
<div class="two-col">
    <div class="section">
        <h2>Risk Score Distribution</h2>
        <div class="risk-bar-wrap">
            <div class="risk-bar-label">
                <span>CRITICAL</span>
                <span>{sc.get('CRITICAL', 0)}</span>
            </div>
            <div class="risk-bar-track">
                <div class="risk-bar-fill fill-critical"
                     style="width:{min(sc.get('CRITICAL',0)*20,100)}%">
                </div>
            </div>
        </div>
        <div class="risk-bar-wrap">
            <div class="risk-bar-label">
                <span>HIGH</span>
                <span>{sc.get('HIGH', 0)}</span>
            </div>
            <div class="risk-bar-track">
                <div class="risk-bar-fill fill-high"
                     style="width:{min(sc.get('HIGH',0)*15,100)}%">
                </div>
            </div>
        </div>
        <div class="risk-bar-wrap">
            <div class="risk-bar-label">
                <span>MEDIUM</span>
                <span>{sc.get('MEDIUM', 0)}</span>
            </div>
            <div class="risk-bar-track">
                <div class="risk-bar-fill fill-medium"
                     style="width:{min(sc.get('MEDIUM',0)*15,100)}%">
            </div>
            </div>
        </div>
        <div class="risk-bar-wrap">
            <div class="risk-bar-label">
                <span>LOW</span>
                <span>{sc.get('LOW', 0)}</span>
            </div>
            <div class="risk-bar-track">
                <div class="risk-bar-fill fill-low"
                     style="width:{min(sc.get('LOW',0)*15,100)}%">
                </div>
            </div>
        </div>
    </div>

    <div class="section">
        <h2>IOC Type Breakdown</h2>
        <div class="stat-row">
            <span class="stat-label">IP Addresses</span>
            <span class="stat-value">{tc.get('ip', 0)}</span>
        </div>
        <div class="stat-row">
            <span class="stat-label">Domains</span>
            <span class="stat-value">{tc.get('domain', 0)}</span>
        </div>
        <div class="stat-row">
            <span class="stat-label">URLs</span>
            <span class="stat-value">{tc.get('url', 0)}</span>
        </div>
        <div class="stat-row">
            <span class="stat-label">File Hashes</span>
            <span class="stat-value">{tc.get('hash', 0)}</span>
        </div>
        <div class="stat-row">
            <span class="stat-label">Email Addresses</span>
            <span class="stat-value">{tc.get('email', 0)}</span>
        </div>
    </div>
</div>

<!-- Critical IOCs -->
<div class="section">
    <h2>Critical IOCs — Immediate Action Required</h2>
    {critical_cards}
</div>

<!-- Top IOCs Table -->
<div class="section">
    <h2>Top IOCs — Ranked by Risk Score</h2>
    <table>
        <thead>
            <tr>
                <th>Score</th>
                <th>Label</th>
                <th>Type</th>
                <th>Value</th>
                <th>Feeds</th>
                <th>Seen In</th>
            </tr>
        </thead>
        <tbody>
            {ioc_rows}
        </tbody>
    </table>
</div>

<!-- Feed Summary + Blocklist Summary -->
<div class="two-col">
    <div class="section">
        <h2>Feed Summary</h2>
        <table>
            <thead>
                <tr>
                    <th>Source</th>
                    <th>Format</th>
                    <th>Entries</th>
                </tr>
            </thead>
            <tbody>
                {feed_rows}
            </tbody>
        </table>
    </div>

    <div class="section">
        <h2>Blocklist Summary</h2>
        <div class="stat-row">
            <span class="stat-label">IP Blocklist</span>
            <span class="stat-value">{bl['ips']} entries</span>
        </div>
        <div class="stat-row">
            <span class="stat-label">Domain Blocklist</span>
            <span class="stat-value">{bl['domains']} entries</span>
        </div>
        <div class="stat-row">
            <span class="stat-label">URL Blocklist</span>
            <span class="stat-value">{bl['urls']} entries</span>
        </div>
        <div class="stat-row">
            <span class="stat-label">Hash Blocklist</span>
            <span class="stat-value">{bl['hashes']} entries</span>
        </div>
        <div class="stat-row">
            <span class="stat-label">Email Blocklist</span>
            <span class="stat-value">{bl['emails']} entries</span>
        </div>
        <div class="stat-row">
            <span class="stat-label">High Priority</span>
            <span class="stat-value">{bl['high_priority']} entries</span>
        </div>
    </div>
</div>

<!-- Footer -->
<div class="footer">
    Threat Intelligence Aggregator (Non-AI) v1.0 &nbsp;|&nbsp;
    Generated: {report['metadata']['generated']} &nbsp;|&nbsp;
    Total IOCs: {s['total_correlated']}
</div>

</body>
</html>"""

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"    [+] HTML report saved: {filename}")
    print(f"    [+] Open in browser  : {filepath}")
    return filepath