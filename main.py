# =============================================================
# Threat Intelligence Aggregator (Non-AI)
# Version : 1.0
# Author  : [Your Name]
# Purpose : Collect, parse, normalize, correlate and export
#           threat intelligence IOCs from multiple feeds.
# =============================================================

import time
from modules.feed_loader   import load_feeds
from modules.ioc_parser    import parse_iocs
from modules.normalizer    import normalize
from modules.correlator    import correlate
from modules.blocklist_gen import generate_blocklists
from modules.reporter      import generate_report

# ── Banner ────────────────────────────────────────────────────
def print_banner():
    print("=" * 60)
    print("   _____ ___   _    _____ _____ ")
    print("  |_   _|_ _| / \\  |_   _|_   _|")
    print("    | |  | |  / _ \\   | |   | |  ")
    print("    | |  | | / ___ \\  | |   | |  ")
    print("    |_| |___/_/   \\_\\ |_|   |_|  ")
    print()
    print("   Threat Intelligence Aggregator")
    print("   Version 1.0 — Non-AI Edition")
    print("=" * 60)


# ── Section printer ───────────────────────────────────────────
def section(title, step, total=6):
    print(f"\n{'─' * 60}")
    print(f"  STEP {step}/{total} — {title.upper()}")
    print(f"{'─' * 60}")


# ── Main pipeline ─────────────────────────────────────────────
def main():
    start_time = time.time()

    print_banner()
    print(f"\n  Starting pipeline at: ", end="")

    import datetime
    print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    # ── Step 1: Load Feeds ────────────────────────────────────
    section("Load IOC Feeds", 1)
    feeds = load_feeds()
    print(f"\n  [✓] Feeds loaded: {len(feeds)}")

    # ── Step 2: Parse IOCs ────────────────────────────────────
    section("Parse IOCs", 2)
    iocs = parse_iocs(feeds)
    print(f"\n  [✓] IOCs parsed: {len(iocs)}")

    # ── Step 3: Normalize ─────────────────────────────────────
    section("Normalize IOCs", 3)
    normalized_iocs = normalize(iocs)
    print(f"\n  [✓] IOCs normalized: {len(normalized_iocs)}")

    # ── Step 4: Correlate + Score ─────────────────────────────
    section("Correlate & Score IOCs", 4)
    correlated_iocs = correlate(normalized_iocs)
    print(f"\n  [✓] IOCs correlated: {len(correlated_iocs)}")

    # ── Step 5: Generate Blocklists ───────────────────────────
    section("Generate Blocklists", 5)
    blocklist_data = generate_blocklists(correlated_iocs)
    print(f"\n  [✓] Blocklists saved to: output/blocklists/")

    # ── Step 6: Generate Report ───────────────────────────────
    section("Generate TI Report", 6)
    report = generate_report(
        feeds,
        iocs,
        normalized_iocs,
        correlated_iocs,
        blocklist_data
    )
    print(f"\n  [✓] Report saved to: output/reports/")

    # ── Final Dashboard ───────────────────────────────────────
    elapsed = round(time.time() - start_time, 2)

    critical = sum(
        1 for i in correlated_iocs
        if i["score_label"] == "CRITICAL"
    )
    high = sum(
        1 for i in correlated_iocs
        if i["score_label"] == "HIGH"
    )
    medium = sum(
        1 for i in correlated_iocs
        if i["score_label"] == "MEDIUM"
    )
    low = sum(
        1 for i in correlated_iocs
        if i["score_label"] == "LOW"
    )

    print(f"\n{'=' * 60}")
    print(f"   PIPELINE COMPLETE — FINAL DASHBOARD")
    print(f"{'=' * 60}")
    print(f"   Runtime               : {elapsed}s")
    print(f"{'─' * 60}")
    print(f"   Feeds processed       : {len(feeds)}")
    print(f"   IOCs parsed           : {len(iocs)}")
    print(f"   IOCs normalized       : {len(normalized_iocs)}")
    print(f"   IOCs correlated       : {len(correlated_iocs)}")
    print(f"{'─' * 60}")
    print(f"   [!!!] CRITICAL IOCs   : {critical}")
    print(f"   [!!]  HIGH IOCs       : {high}")
    print(f"   [!]   MEDIUM IOCs     : {medium}")
    print(f"   [ ]   LOW IOCs        : {low}")
    print(f"{'─' * 60}")
    print(f"   Blocklists location   : output/blocklists/")
    print(f"   Report location       : output/reports/")
    print(f"{'=' * 60}")
    print(f"\n  Top 3 Highest Risk IOCs:")
    print(f"  {'SCORE':<7} {'LABEL':<10} {'TYPE':<10} VALUE")
    print(f"  {'─' * 55}")
    for ioc in correlated_iocs[:3]:
        print(
            f"  {ioc['risk_score']:<7} "
            f"{ioc['score_label']:<10} "
            f"{ioc['type']:<10} "
            f"{ioc['value']}"
        )
    print(f"\n{'=' * 60}")
    print(f"   Threat Intelligence Aggregator — Run Complete")
    print(f"{'=' * 60}\n")


# ── Entry point ───────────────────────────────────────────────
if __name__ == "__main__":
    main()