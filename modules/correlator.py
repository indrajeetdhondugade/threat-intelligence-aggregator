# correlator.py — Correlates IOCs and assigns risk scores

from collections import defaultdict

# Risk score thresholds
RISK_THRESHOLDS = {
    3: "critical",
    2: "high",
    1: "medium"
}

# Base score per IOC type
TYPE_SCORE = {
    "ip"    : 10,
    "domain": 10,
    "url"   : 20,
    "hash"  : 20,
    "email" : 5
}

# Keywords that increase score
HIGH_RISK_KEYWORDS = [
    "malware", "trojan", "botnet", "phishing",
    "ransomware", "exploit", "c2", "evil", "bad",
    "attack", "steal", "drop"
]


def get_risk_level(feed_count):
    """Return risk level based on feed count."""
    for threshold, level in RISK_THRESHOLDS.items():
        if feed_count >= threshold:
            return level
    return "low"


def calculate_score(ioc_value, ioc_type, feed_count):
    """
    Calculate a numeric risk score for an IOC.
    Score is based on:
    - Feed count  : feed_count x 25 (max 75)
    - Type bonus  : based on IOC type (max 20)
    - Keyword bonus: +15 if high-risk keyword found
    Total max = 100
    """
    # Base score from feed count (max 75)
    feed_score = min(feed_count * 25, 75)

    # Type bonus
    type_score = TYPE_SCORE.get(ioc_type, 5)

    # Keyword bonus
    keyword_score = 0
    value_lower = ioc_value.lower()
    for keyword in HIGH_RISK_KEYWORDS:
        if keyword in value_lower:
            keyword_score = 15
            break

    # Total score capped at 100
    total = min(feed_score + type_score + keyword_score, 100)
    return total


def get_score_label(score):
    """Convert numeric score to a readable label."""
    if score >= 80:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH"
    elif score >= 40:
        return "MEDIUM"
    else:
        return "LOW"


def correlate(normalized_iocs):
    """
    Find IOCs across multiple feeds and assign risk scores.
    Returns a sorted list of correlated IOCs.
    """
    print("\n[*] Running correlation engine with scoring...")

    # Step 1: Group IOCs by value and track feeds
    ioc_feed_map = defaultdict(set)
    ioc_details  = {}

    for ioc in normalized_iocs:
        value  = ioc["value"]
        source = ioc["source"]

        ioc_feed_map[value].add(source)

        if value not in ioc_details:
            ioc_details[value] = {
                "type"     : ioc["type"],
                "value"    : value,
                "category" : ioc["category"],
                "severity" : ioc["severity"],
                "timestamp": ioc["timestamp"]
            }

    # Step 2: Build correlated results with scores
    correlated = []

    for value, feeds in ioc_feed_map.items():
        feed_count  = len(feeds)
        risk_level  = get_risk_level(feed_count)
        risk_score  = calculate_score(
            value,
            ioc_details[value]["type"],
            feed_count
        )
        score_label = get_score_label(risk_score)

        correlated_ioc = {
            "type"       : ioc_details[value]["type"],
            "value"      : value,
            "category"   : ioc_details[value]["category"],
            "severity"   : ioc_details[value]["severity"],
            "feeds"      : list(feeds),
            "feed_count" : feed_count,
            "risk_level" : risk_level,
            "risk_score" : risk_score,
            "score_label": score_label,
            "timestamp"  : ioc_details[value]["timestamp"]
        }

        correlated.append(correlated_ioc)

    # Step 3: Sort by risk score (highest first)
    correlated.sort(key=lambda x: x["risk_score"], reverse=True)

    # Step 4: Print summary
    print(f"\n    Total IOCs scored : {len(correlated)}")
    print(f"\n    Score distribution:")
    for label in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = sum(1 for i in correlated if i["score_label"] == label)
        print(f"        {label:<10}: {count}")

    # Step 5: Print top priority IOCs
    print(f"\n[!] Top Priority IOCs (sorted by risk score):")
    print(f"    {'SCORE':<7} {'LABEL':<10} {'TYPE':<10} {'VALUE':<35} {'FEEDS'}")
    print("    " + "-" * 75)
    for ioc in correlated:
        feeds_str = ", ".join(ioc["feeds"])
        print(f"    {ioc['risk_score']:<7} {ioc['score_label']:<10} {ioc['type']:<10} {ioc['value']:<35} {feeds_str}")

    return correlated