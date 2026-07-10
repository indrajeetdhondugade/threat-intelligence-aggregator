# feed_loader.py — Loads IOC feeds from the feeds/ folder

import os
import json
import csv

FEEDS_FOLDER = "feeds"

def load_feeds():
    all_feeds = []

    print("\n[*] Loading feeds from folder:", FEEDS_FOLDER)

    # Get all files inside the feeds folder
    for filename in os.listdir(FEEDS_FOLDER):
        filepath = os.path.join(FEEDS_FOLDER, filename)

        print(f"    [+] Found file: {filename}")

        if filename.endswith(".txt"):
            data = load_txt(filepath, filename)
            all_feeds.append(data)

        elif filename.endswith(".csv"):
            data = load_csv(filepath, filename)
            all_feeds.append(data)

        elif filename.endswith(".json"):
            data = load_json(filepath, filename)
            all_feeds.append(data)

        else:
            print(f"    [!] Skipping unsupported file: {filename}")

    print(f"\n[*] Total feeds loaded: {len(all_feeds)}")
    return all_feeds


def load_txt(filepath, filename):
    lines = []
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            # Skip empty lines and comments
            if line and not line.startswith("#"):
                lines.append(line)
    return {
        "source": filename,
        "format": "txt",
        "raw_lines": lines
    }


def load_csv(filepath, filename):
    rows = []
    with open(filepath, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(dict(row))
    return {
        "source": filename,
        "format": "csv",
        "raw_lines": rows
    }


def load_json(filepath, filename):
    with open(filepath, "r") as f:
        data = json.load(f)
    return {
        "source": filename,
        "format": "json",
        "raw_lines": data.get("indicators", [])
    }