# ioc_parser.py — Extracts and validates IOCs from loaded feed data

import re
import ipaddress

# --- Regex Patterns ---
PATTERNS = {
    "ip":     r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "domain": r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|ru|xyz|io|gov|edu|info|co)\b",
    "url":    r"https?://[^\s,\"']+",
    "hash":   r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b",
    "email":  r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
}

# IPs to ignore — private, loopback, broadcast
INVALID_IPS = {
    "0.0.0.0",
    "255.255.255.255",
    "127.0.0.1",
    "localhost"
}

# Domains to ignore — too generic or invalid
INVALID_DOMAINS = {
    "example.com",
    "test.com",
    "localhost.com"
}


def is_valid_ip(ip_str):
    """Check if a string is a valid public IP address."""
    try:
        ip = ipaddress.ip_address(ip_str)
        # Reject private, loopback, and reserved IPs
        if ip.is_private or ip.is_loopback or ip.is_reserved:
            return False
        if ip_str in INVALID_IPS:
            return False
        return True
    except ValueError:
        return False


def is_valid_domain(domain_str):
    """Check if a domain is valid and not in the ignore list."""
    if domain_str in INVALID_DOMAINS:
        return False
    if len(domain_str) < 4:
        return False
    return True


def is_valid_hash(hash_str):
    """Check if a hash is a known valid length (MD5, SHA1, SHA256)."""
    return len(hash_str) in [32, 40, 64]


def clean_url(url_str):
    """Remove trailing punctuation from URLs."""
    return url_str.rstrip(".,;:)\"'")


def extract_iocs_from_text(text, source):
    """Extract all IOC types from a single text string."""
    extracted = []

    for ioc_type, pattern in PATTERNS.items():
        matches = re.findall(pattern, text)

        for match in matches:
            match = match.strip()

            # Validate based on type
            if ioc_type == "ip":
                if not is_valid_ip(match):
                    continue

            elif ioc_type == "domain":
                if not is_valid_domain(match):
                    continue

            elif ioc_type == "hash":
                if not is_valid_hash(match):
                    continue

            elif ioc_type == "url":
                match = clean_url(match)

            extracted.append({
                "type":   ioc_type,
                "value":  match,
                "source": source
            })

    return extracted


def parse_iocs(feeds):
    """Parse IOCs from all loaded feeds."""
    all_iocs = []

    print("\n[*] Parsing IOCs from loaded feeds...")

    for feed in feeds:
        source = feed["source"]
        fmt    = feed["format"]
        lines  = feed["raw_lines"]
        feed_iocs = []

        print(f"\n    [+] Parsing: {source} (format: {fmt})")

        for entry in lines:
            # Convert each entry to plain text for regex scanning
            if isinstance(entry, dict):
                text = " ".join(str(v) for v in entry.values())
            else:
                text = str(entry).strip()

            # Skip empty lines
            if not text:
                continue

            iocs = extract_iocs_from_text(text, source)
            feed_iocs.extend(iocs)

        print(f"        IOCs found in this feed: {len(feed_iocs)}")
        all_iocs.extend(feed_iocs)

    # Remove duplicates PER FEED only
    # Keep one entry per (type, value, source) combination
    seen = set()
    unique_iocs = []
    for ioc in all_iocs:
        key = (ioc["type"], ioc["value"], ioc["source"])
        if key not in seen:
            seen.add(key)
            unique_iocs.append(ioc)

            # Print final summary
    print(f"\n[*] Total unique IOCs extracted: {len(unique_iocs)}")
    for ioc_type in PATTERNS.keys():
        count = sum(1 for i in unique_iocs if i["type"] == ioc_type)
        print(f"    {ioc_type.upper():<10}: {count}")

    return unique_iocs