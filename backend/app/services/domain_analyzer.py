from urllib.parse import urlparse
import socket


def analyze_domain(url: str):
    """
    Analyze domain and DNS information for a URL.

    This is a passive analysis only:
    - extracts the hostname
    - checks DNS resolution
    - gets resolved IP addresses
    - checks whether DNS records exist
    - identifies the hostname
    """

    # ---------------------------------------------------------
    # Parse URL
    # ---------------------------------------------------------

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)

    hostname = parsed.hostname or ""

    # ---------------------------------------------------------
    # Basic result
    # ---------------------------------------------------------

    result = {
        "hostname": hostname,
        "domain_exists": False,
        "dns_record": False,
        "ip_addresses": [],
        "ip_address_count": 0,
        "dns_error": None,
    }

    # ---------------------------------------------------------
    # Invalid hostname
    # ---------------------------------------------------------

    if not hostname:
        result["dns_error"] = "No hostname found"
        return result

    # ---------------------------------------------------------
    # DNS lookup
    # ---------------------------------------------------------

    try:

        addresses = socket.getaddrinfo(
            hostname,
            None
        )

        ip_addresses = set()

        for address in addresses:

            ip = address[4][0]

            if ip:
                ip_addresses.add(ip)

        result["ip_addresses"] = sorted(ip_addresses)

        result["ip_address_count"] = len(
            ip_addresses
        )

        if ip_addresses:
            result["domain_exists"] = True
            result["dns_record"] = True

    except socket.gaierror as error:

        result["dns_error"] = str(error)

    except Exception as error:

        result["dns_error"] = str(error)

    # ---------------------------------------------------------
    # Return result
    # ---------------------------------------------------------

    return result