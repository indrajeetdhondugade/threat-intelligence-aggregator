# blocklist_gen.py — Generates professional blocklist files

import os
import json
import csv
from datetime import datetime

OUTPUT_DIR = "output/blocklists"


def generate_blocklists(correlated_iocs):
    """
    Generate all blocklist files from correlated IOCs.
    Exports in TXT, CSV and JSON formats.
    """
    print("\n[*] Generating blocklists...")

    # Ensure output directory exists
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # Separate IOCs by type
    ips     = [i for i in correlated_iocs if i["type"] == "ip"]
    domains = [i for i in correlated_iocs if i["type"] == "domain"]
    urls    = [i for i in correlated_iocs if i["type"] == "url"]
    hashes  = [i for i in correlated_iocs if i["type"] == "hash"]
    emails  = [i for i in correlated_iocs if i["type"] == "email"]

    # High priority only (score >= 60)
    high_priority = [
        i for i in correlated_iocs
        if i["risk_score"] >= 60
    ]

    print(f"\n    IOC breakdown:")
    print(f"    IPs           : {len(ips)}")
    print(f"    Domains       : {len(domains)}")
    print(f"    URLs          : {len(urls)}")
    print(f"    Hashes        : {len(hashes)}")
    print(f"    Emails        : {len(emails)}")
    print(f"    High priority : {len(high_priority)} (score >= 60)")

    # Generate all blocklists
    _generate_ip_blocklist(ips)
    _generate_domain_blocklist(domains)
    _generate_url_blocklist(urls)
    _generate_hash_blocklist(hashes)
    _generate_email_blocklist(emails)
    _generate_high_priority_blocklist(high_priority)
    _generate_combined_blocklist(correlated_iocs)

    print(f"\n[+] All blocklists saved to: {OUTPUT_DIR}/")
    return {
        "ips"          : ips,
        "domains"      : domains,
        "urls"         : urls,
        "hashes"       : hashes,
        "emails"       : emails,
        "high_priority": high_priority,
        "all"          : correlated_iocs
    }


def _get_header(title, ioc_count, ioc_type="mixed"):
    """Generate a professional header for TXT blocklists."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return [
        "#" + "=" * 50,
        f"# {title}",
        "#" + "=" * 50,
        f"# Generated   : {now}",
        f"# Tool        : Threat Intelligence Aggregator (Non-AI)",
        f"# IOC Type    : {ioc_type.upper()}",
        f"# Total entries: {ioc_count}",
        "#" + "-" * 50,
        "# USAGE:",
        "# - IPs     : Load into firewall deny rules",
        "# - Domains : Load into DNS sinkhole / filter",
        "# - URLs    : Load into web proxy blocklist",
        "# - Hashes  : Load into EDR / AV blocklist",
        "#" + "=" * 50,
        ""
    ]


def _write_txt(filename, header_lines, ioc_list):
    """Write a professional TXT blocklist."""
    filepath = os.path.join(OUTPUT_DIR, filename)
    with open(filepath, "w") as f:
        for line in header_lines:
            f.write(line + "\n")
        for ioc in ioc_list:
            # Add inline comment with risk score
            f.write(
                f"{ioc['value']:<45} "
                f"# score:{ioc['risk_score']} "
                f"feeds:{ioc['feed_count']} "
                f"label:{ioc['score_label']}\n"
            )
    print(f"    [+] Saved: {filename:<35} ({len(ioc_list)} entries)")


def _write_csv(filename, ioc_list):
    """Write a CSV blocklist."""
    filepath = os.path.join(OUTPUT_DIR, filename)
    with open(filepath, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "type", "value", "risk_score",
            "score_label", "feed_count", "feeds", "timestamp"
        ])
        writer.writeheader()
        for ioc in ioc_list:
            writer.writerow({
                "type"       : ioc["type"],
                "value"      : ioc["value"],
                "risk_score" : ioc["risk_score"],
                "score_label": ioc["score_label"],
                "feed_count" : ioc["feed_count"],
                "feeds"      : ", ".join(ioc["feeds"]),
                "timestamp"  : ioc["timestamp"]
            })
    print(f"    [+] Saved: {filename:<35} ({len(ioc_list)} entries)")


def _write_json(filename, ioc_list, title="Blocklist"):
    """Write a JSON blocklist."""
    filepath = os.path.join(OUTPUT_DIR, filename)
    output = {
        "title"      : title,
        "generated"  : datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "tool"       : "Threat Intelligence Aggregator (Non-AI)",
        "total"      : len(ioc_list),
        "indicators" : ioc_list
    }
    with open(filepath, "w") as f:
        json.dump(output, f, indent=4)
    print(f"    [+] Saved: {filename:<35} ({len(ioc_list)} entries)")


def _generate_ip_blocklist(ips):
    print(f"\n    [*] IP blocklists:")
    if not ips:
        print(f"        No IPs to export.")
        return
    header = _get_header("Malicious IP Blocklist", len(ips), "ip")
    _write_txt("ip_blocklist.txt",    header, ips)
    _write_csv("ip_blocklist.csv",    ips)
    _write_json("ip_blocklist.json",  ips, "Malicious IP Blocklist")


def _generate_domain_blocklist(domains):
    print(f"\n    [*] Domain blocklists:")
    if not domains:
        print(f"        No domains to export.")
        return
    header = _get_header("Malicious Domain Blocklist", len(domains), "domain")
    _write_txt("domain_blocklist.txt",   header, domains)
    _write_csv("domain_blocklist.csv",   domains)
    _write_json("domain_blocklist.json", domains, "Malicious Domain Blocklist")


def _generate_url_blocklist(urls):
    print(f"\n    [*] URL blocklists:")
    if not urls:
        print(f"        No URLs to export.")
        return
    header = _get_header("Malicious URL Blocklist", len(urls), "url")
    _write_txt("url_blocklist.txt",   header, urls)
    _write_csv("url_blocklist.csv",   urls)
    _write_json("url_blocklist.json", urls, "Malicious URL Blocklist")


def _generate_hash_blocklist(hashes):
    print(f"\n    [*] Hash blocklists:")
    if not hashes:
        print(f"        No hashes to export.")
        return
    header = _get_header("Malicious File Hash Blocklist", len(hashes), "hash")
    _write_txt("hash_blocklist.txt",   header, hashes)
    _write_csv("hash_blocklist.csv",   hashes)
    _write_json("hash_blocklist.json", hashes, "Malicious Hash Blocklist")


def _generate_email_blocklist(emails):
    print(f"\n    [*] Email blocklists:")
    if not emails:
        print(f"        No emails to export.")
        return
    header = _get_header("Malicious Email Blocklist", len(emails), "email")
    _write_txt("email_blocklist.txt",   header, emails)
    _write_csv("email_blocklist.csv",   emails)
    _write_json("email_blocklist.json", emails, "Malicious Email Blocklist")


def _generate_high_priority_blocklist(high_priority):
    print(f"\n    [*] High priority blocklist:")
    if not high_priority:
        print(f"        No high priority IOCs.")
        return
    header = _get_header(
        "HIGH PRIORITY Blocklist — Score >= 60",
        len(high_priority), "mixed"
    )
    _write_txt("high_priority_blocklist.txt",
               header, high_priority)
    _write_csv("high_priority_blocklist.csv",   high_priority)
    _write_json("high_priority_blocklist.json",
                high_priority, "High Priority Blocklist")


def _generate_combined_blocklist(all_iocs):
    print(f"\n    [*] Combined blocklist:")
    header = _get_header(
        "Combined IOC Blocklist — All Types",
        len(all_iocs), "mixed"
    )
    _write_txt("combined_blocklist.txt",   header, all_iocs)
    _write_csv("combined_blocklist.csv",   all_iocs)
    _write_json("combined_blocklist.json", all_iocs, "Combined IOC Blocklist")