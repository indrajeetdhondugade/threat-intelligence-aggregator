# normalizer.py — Normalizes IOCs into a unified structured format

from datetime import datetime

# --- Category mapping by IOC type ---
CATEGORY_MAP = {
    "ip"    : "network",
    "domain": "network",
    "url"   : "web",
    "hash"  : "file",
    "email" : "email"
}

# --- Default severity by IOC type ---
DEFAULT_SEVERITY = {
    "ip"    : "medium",
    "domain": "medium",
    "url"   : "high",
    "hash"  : "high",
    "email" : "low"
}

# --- Keywords that indicate higher severity ---
HIGH_RISK_KEYWORDS = [
    "malware", "trojan", "botnet", "phishing",
    "ransomware", "exploit", "c2", "evil", "bad",
    "attack", "steal", "drop"
]


def get_severity(ioc_value, ioc_type):
    """
    Determine severity based on IOC type and value keywords.
    If the value contains a high-risk keyword, bump to high.
    """
    base_severity = DEFAULT_SEVERITY.get(ioc_type, "low")

    # Check if the IOC value contains any high-risk keywords
    value_lower = ioc_value.lower()
    for keyword in HIGH_RISK_KEYWORDS:
        if keyword in value_lower:
            return "high"

    return base_severity


def normalize(iocs):
    """Normalize a list of raw IOCs into unified structured records."""
    normalized = []

    print("\n[*] Normalizing IOCs...")

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    for ioc in iocs:
        ioc_type  = ioc.get("type", "unknown")
        ioc_value = ioc.get("value", "").strip().lower()
        source    = ioc.get("source", "unknown")

        # Skip empty values
        if not ioc_value:
            continue

        category = CATEGORY_MAP.get(ioc_type, "unknown")
        severity = get_severity(ioc_value, ioc_type)

        normalized_ioc = {
            "type"     : ioc_type,
            "value"    : ioc_value,
            "source"   : source,
            "category" : category,
            "severity" : severity,
            "timestamp": timestamp,
            "status"   : "active"
        }

        normalized.append(normalized_ioc)

    # Print summary
    print(f"    Total normalized IOCs : {len(normalized)}")
    print(f"\n    Severity breakdown:")

    for level in ["high", "medium", "low"]:
        count = sum(1 for i in normalized if i["severity"] == level)
        print(f"        {level.upper():<10}: {count}")

    print(f"\n    Category breakdown:")
    for cat in ["network", "web", "file", "email"]:
        count = sum(1 for i in normalized if i["category"] == cat)
        print(f"        {cat.upper():<10}: {count}")

    return normalized