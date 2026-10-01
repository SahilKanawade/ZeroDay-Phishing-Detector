from urllib.parse import urlparse
import ipaddress


# ==========================================================
# KNOWN SUSPICIOUS URL PATTERNS
# ==========================================================

SUSPICIOUS_KEYWORDS = [
    "login",
    "signin",
    "verify",
    "verification",
    "secure",
    "account",
    "update",
    "confirm",
    "password",
    "credential",
    "bank",
    "payment",
    "wallet",
    "support",
    "recover",
    "unlock",
]


# ==========================================================
# SUSPICIOUS DOMAIN PATTERNS
# ==========================================================

SUSPICIOUS_TLDS = {
    ".zip",
    ".mov",
    ".click",
    ".top",
    ".xyz",
    ".work",
    ".tk",
    ".ml",
    ".ga",
    ".cf",
    ".gq",
}


def check_ip_address(hostname):
    """
    Determine whether the hostname is an IP address.
    """

    if not hostname:
        return False

    try:
        ipaddress.ip_address(hostname)
        return True

    except ValueError:
        return False


def analyze_threat_intelligence(url):
    """
    Perform local threat-intelligence style analysis.

    This is an indicator-based layer.
    It does NOT claim that a URL is malicious merely
    because one indicator is present.
    """

    result = {
        "threat_intelligence_available": True,

        "reputation_status": "unknown",

        "suspicious_keyword_count": 0,
        "suspicious_keywords": [],

        "suspicious_tld": False,
        "tld": "",

        "ip_based_url": False,

        "domain_length": 0,

        "threat_indicators": [],

        "threat_score": 0,

        "threat_level": "low",
    }


    # ==========================================================
    # NORMALIZE URL
    # ==========================================================

    if not url.startswith(("http://", "https://")):
        url = "http://" + url


    parsed = urlparse(url)

    hostname = (
        parsed.hostname or ""
    ).lower()


    full_url = url.lower()


    # ==========================================================
    # DOMAIN LENGTH
    # ==========================================================

    result["domain_length"] = len(hostname)


    # ==========================================================
    # IP-BASED URL
    # ==========================================================

    if check_ip_address(hostname):

        result["ip_based_url"] = True

        result["threat_indicators"].append(
            "URL uses an IP address instead of a domain"
        )

        result["threat_score"] += 20


    # ==========================================================
    # SUSPICIOUS KEYWORDS
    # ==========================================================

    detected_keywords = []

    for keyword in SUSPICIOUS_KEYWORDS:

        if keyword in full_url:

            detected_keywords.append(
                keyword
            )


    # Remove duplicates while preserving order

    detected_keywords = list(
        dict.fromkeys(
            detected_keywords
        )
    )


    result["suspicious_keywords"] = (
        detected_keywords
    )

    result["suspicious_keyword_count"] = (
        len(detected_keywords)
    )


    if len(detected_keywords) >= 4:

        result["threat_score"] += 20

        result["threat_indicators"].append(
            "Multiple credential or account-related keywords detected"
        )

    elif len(detected_keywords) >= 2:

        result["threat_score"] += 10

        result["threat_indicators"].append(
            "Multiple suspicious keywords detected"
        )

    elif len(detected_keywords) == 1:

        result["threat_score"] += 5

        result["threat_indicators"].append(
            "Suspicious keyword detected"
        )


    # ==========================================================
    # TOP-LEVEL DOMAIN
    # ==========================================================

    matched_tld = ""

    for tld in SUSPICIOUS_TLDS:

        if hostname.endswith(tld):

            matched_tld = tld
            break


    if matched_tld:

        result["suspicious_tld"] = True
        result["tld"] = matched_tld

        result["threat_score"] += 10

        result["threat_indicators"].append(
            f"Domain uses a TLD included in the local indicator list: "
            f"{matched_tld}"
        )

    else:

        # Extract normal TLD for information
        parts = hostname.split(".")

        if len(parts) >= 2:

            result["tld"] = (
                "." + parts[-1]
            )


    # ==========================================================
    # LONG DOMAIN
    # ==========================================================

    if len(hostname) > 30:

        result["threat_score"] += 5

        result["threat_indicators"].append(
            "Domain name is unusually long"
        )


    # ==========================================================
    # EXCESSIVE HYPHENS
    # ==========================================================

    hyphen_count = hostname.count("-")

    if hyphen_count >= 2:

        result["threat_score"] += 5

        result["threat_indicators"].append(
            "Multiple hyphens detected in domain"
        )


    # ==========================================================
    # HTTPS
    # ==========================================================

    if parsed.scheme == "https":

        result["threat_indicators"].append(
            "HTTPS is present; encryption alone does not establish trust"
        )


    # ==========================================================
    # LIMIT SCORE
    # ==========================================================

    result["threat_score"] = min(
        max(
            result["threat_score"],
            0
        ),
        100
    )


    # ==========================================================
    # THREAT LEVEL
    # ==========================================================

    if result["threat_score"] >= 50:

        result["threat_level"] = "high"

    elif result["threat_score"] >= 25:

        result["threat_level"] = "medium"

    else:

        result["threat_level"] = "low"


    # ==========================================================
    # REPUTATION STATUS
    # ==========================================================

    # No external reputation provider is connected yet.
    result["reputation_status"] = "not_checked"


    return result