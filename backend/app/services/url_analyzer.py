from urllib.parse import urlparse
import ipaddress
import re


SUSPICIOUS_KEYWORDS = [
    "login",
    "signin",
    "verify",
    "verification",
    "secure",
    "account",
    "update",
    "password",
    "bank",
    "confirm",
    "authenticate",
    "wallet",
]


SHORTENING_SERVICES = [
    "bit.ly",
    "tinyurl.com",
    "goo.gl",
    "t.co",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "rebrand.ly",
    "cutt.ly",
    "shorturl.at",
]


def is_ip_address(hostname):
    if not hostname:
        return False

    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def analyze_url(url: str):

    original_url = url

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)

    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""

    url_lower = url.lower()
    hostname_lower = hostname.lower()

    # --------------------------------------------------
    # Basic URL features
    # --------------------------------------------------

    raw_url_length = len(url)

    hostname_parts = [
        part for part in hostname.split(".") if part
    ]

    subdomain_count = max(
        len(hostname_parts) - 2,
        0
    )

    suspicious_keywords = [
        keyword
        for keyword in SUSPICIOUS_KEYWORDS
        if keyword in url_lower
    ]

    # --------------------------------------------------
    # IP address
    # --------------------------------------------------

    has_ip = int(is_ip_address(hostname))

    # --------------------------------------------------
    # URL shortening service
    # --------------------------------------------------

    shortining_service = int(
        hostname_lower in SHORTENING_SERVICES
    )

    # --------------------------------------------------
    # @ symbol
    # --------------------------------------------------

    having_at_symbol = int("@" in url)

    # --------------------------------------------------
    # Double slash redirecting
    # Look for // after the protocol
    # --------------------------------------------------

    after_protocol = re.sub(
        r"^https?://",
        "",
        url_lower
    )

    double_slash_redirecting = int(
        "//" in after_protocol
    )

    # --------------------------------------------------
    # Prefix / suffix
    # --------------------------------------------------

    prefix_suffix = -1 if "-" in hostname else 1

    # --------------------------------------------------
    # Subdomain
    # UCI-style encoding:
    # 0 subdomains -> 1
    # 1 subdomain  -> 0
    # 2+           -> -1
    # --------------------------------------------------

    if subdomain_count == 0:
        having_sub_domain = 1
    elif subdomain_count == 1:
        having_sub_domain = 0
    else:
        having_sub_domain = -1

    # --------------------------------------------------
    # URL length
    # UCI-style encoding:
    # < 54  -> 1
    # 54-75 -> 0
    # > 75  -> -1
    # --------------------------------------------------

    if raw_url_length < 54:
        uci_url_length = 1
    elif raw_url_length <= 75:
        uci_url_length = 0
    else:
        uci_url_length = -1

    # --------------------------------------------------
    # HTTPS
    # --------------------------------------------------

    sslfinal_state = int(
        parsed.scheme == "https"
    )

    https_token = -1 if "https" in hostname_lower else 1

    # --------------------------------------------------
    # Port
    # --------------------------------------------------

    try:
        port = parsed.port

        if port is None:
            has_port = 0
            uci_port = -1
        elif port in (80, 443):
            has_port = 1
            uci_port = -1
        else:
            has_port = 1
            uci_port = 1

    except ValueError:
        port = None
        has_port = 1
        uci_port = 1

    # --------------------------------------------------
    # Request URL
    #
    # Exact UCI calculation requires HTML resource
    # analysis, so keep placeholder for now.
    # --------------------------------------------------

    request_url = 0

    # --------------------------------------------------
    # Abnormal URL
    #
    # Full UCI implementation requires additional
    # domain/host information.
    # This is currently an approximation.
    # --------------------------------------------------

    abnormal_url = -1 if "@" in url else 1

    # --------------------------------------------------
    # Additional URL statistics
    # --------------------------------------------------

    dot_count = url.count(".")
    hyphen_count = url.count("-")
    slash_count = url.count("/")
    question_mark_count = url.count("?")
    equal_count = url.count("=")

    # --------------------------------------------------
    # Return feature set
    # --------------------------------------------------

    return {

        # Original URL
        "original_url": original_url,

        # Normalized URL used internally
        "normalized_url": url,

        # Custom URL features
        "raw_url_length": raw_url_length,
        "hostname_length": len(hostname),
        "path_length": len(path),

        "https": sslfinal_state,

        "dot_count": dot_count,
        "hyphen_count": hyphen_count,
        "slash_count": slash_count,
        "question_mark_count": question_mark_count,
        "equal_count": equal_count,

        "at_symbol": having_at_symbol,

        "subdomain_count": subdomain_count,

        "has_ip_address": has_ip,
        "has_port": has_port,

        "suspicious_keyword_count": len(
            suspicious_keywords
        ),

        "suspicious_keywords": suspicious_keywords,

        # --------------------------------------------------
        # UCI / ML compatible features
        # --------------------------------------------------

        "having_ip_address": -1 if has_ip else 1,

        "url_length": uci_url_length,

        "shortining_service": (
            -1 if shortining_service else 1
        ),

        "having_at_symbol": (
            -1 if having_at_symbol else 1
        ),

        "double_slash_redirecting": (
            -1 if double_slash_redirecting else 1
        ),

        "prefix_suffix": prefix_suffix,

        "having_sub_domain": having_sub_domain,

        "sslfinal_state": sslfinal_state,

        "port": uci_port,

        "https_token": https_token,

        "request_url": request_url,

        "abnormal_url": abnormal_url,
    }