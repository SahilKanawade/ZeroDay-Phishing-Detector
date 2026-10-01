import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin


REQUEST_TIMEOUT = 8

USER_AGENT = (
    "Mozilla/5.0 "
    "(Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 "
    "(KHTML, like Gecko) "
    "Chrome/140.0 Safari/537.36"
)


def fetch_webpage(url: str):
    try:
        response = requests.get(
            url,
            headers={"User-Agent": USER_AGENT},
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True
        )

        return response

    except requests.RequestException:
        return None


def is_external_url(resource_url, page_hostname):
    """
    Check whether a resource belongs to an external hostname.
    """

    if not resource_url:
        return False

    parsed = urlparse(resource_url)

    resource_hostname = (
        parsed.hostname or ""
    ).lower()

    if not resource_hostname:
        return False

    return resource_hostname != page_hostname


def analyze_html(url: str):

    result = {
        "page_reachable": False,
        "status_code": None,
        "final_url": None,
        "content_type": None,

        "page_title": "",

        # Forms
        "forms": 0,
        "password_inputs": 0,
        "external_form_actions": 0,
        "email_form_actions": 0,

        # Links
        "total_anchors": 0,
        "external_links": 0,
        "internal_links": 0,

        # Resources
        "total_resources": 0,
        "external_resources": 0,
        "internal_resources": 0,

        "images": 0,
        "external_images": 0,

        "scripts": 0,
        "external_scripts": 0,

        "stylesheets": 0,
        "external_stylesheets": 0,

        # Other HTML
        "iframe_count": 0,
        "hidden_elements": 0,
        "favicon_present": False,

        # JavaScript behavior
        "onmouseover_present": False,
        "rightclick_blocking": False,
        "popup_behavior": False,
        "suspicious_javascript": False,

        # UCI-style helper information
        "request_url_external_percentage": 0.0,
        "anchor_external_percentage": 0.0,
        "links_in_tags_external_percentage": 0.0,

        # Error
        "html_analysis_error": None,
    }

    # --------------------------------------------------
    # FETCH PAGE
    # --------------------------------------------------

    response = fetch_webpage(url)

    if response is None:
        result["html_analysis_error"] = "Unable to fetch webpage"
        return result

    result["page_reachable"] = True
    result["status_code"] = response.status_code
    result["final_url"] = response.url
    result["content_type"] = response.headers.get(
        "Content-Type",
        ""
    )

    # Only analyze HTML pages
    if "text/html" not in result["content_type"].lower():

        result["html_analysis_error"] = (
            "Response is not HTML"
        )

        return result

    # --------------------------------------------------
    # PARSE HTML
    # --------------------------------------------------

    soup = BeautifulSoup(
        response.text,
        "html.parser"
    )

    parsed_page_url = urlparse(response.url)

    page_hostname = (
        parsed_page_url.hostname or ""
    ).lower()

    # --------------------------------------------------
    # PAGE TITLE
    # --------------------------------------------------

    title = soup.find("title")

    if title:
        result["page_title"] = title.get_text(
            strip=True
        )

    # --------------------------------------------------
    # FORMS
    # --------------------------------------------------

    forms = soup.find_all("form")

    result["forms"] = len(forms)

    # Password fields
    password_inputs = soup.find_all(
        "input",
        attrs={"type": "password"}
    )

    result["password_inputs"] = len(
        password_inputs
    )

    # Form actions
    for form in forms:

        action = form.get("action")

        if not action:
            continue

        action_lower = action.lower()

        # Detect email submission
        if action_lower.startswith("mailto:"):
            result["email_form_actions"] += 1
            continue

        parsed_action = urlparse(
            urljoin(
                response.url,
                action
            )
        )

        action_hostname = (
            parsed_action.hostname or ""
        ).lower()

        if (
            action_hostname
            and action_hostname != page_hostname
        ):
            result["external_form_actions"] += 1

    # --------------------------------------------------
    # ANCHOR LINKS
    # --------------------------------------------------

    anchors = soup.find_all("a")

    result["total_anchors"] = len(anchors)

    for anchor in anchors:

        href = anchor.get("href")

        if not href:
            continue

        href_lower = href.lower()

        if href_lower.startswith(
            (
                "#",
                "javascript:",
                "mailto:",
                "tel:"
            )
        ):
            continue

        absolute_url = urljoin(
            response.url,
            href
        )

        parsed_link = urlparse(
            absolute_url
        )

        link_hostname = (
            parsed_link.hostname or ""
        ).lower()

        if not link_hostname:
            continue

        if link_hostname == page_hostname:

            result["internal_links"] += 1

        else:

            result["external_links"] += 1

    # Anchor percentage
    valid_anchors = (
        result["internal_links"]
        + result["external_links"]
    )

    if valid_anchors > 0:

        result["anchor_external_percentage"] = (
            result["external_links"]
            / valid_anchors
            * 100
        )

    # --------------------------------------------------
    # IMAGES
    # --------------------------------------------------

    images = soup.find_all("img")

    result["images"] = len(images)

    for image in images:

        src = image.get("src")

        if not src:
            continue

        absolute_url = urljoin(
            response.url,
            src
        )

        if is_external_url(
            absolute_url,
            page_hostname
        ):
            result["external_images"] += 1

    # --------------------------------------------------
    # SCRIPTS
    # --------------------------------------------------

    scripts = soup.find_all("script")

    result["scripts"] = len(scripts)

    for script in scripts:

        src = script.get("src")

        if not src:
            continue

        absolute_url = urljoin(
            response.url,
            src
        )

        if is_external_url(
            absolute_url,
            page_hostname
        ):
            result["external_scripts"] += 1

    # --------------------------------------------------
    # STYLESHEETS
    # --------------------------------------------------

    stylesheet_links = soup.find_all(
        "link",
        attrs={"rel": lambda value:
               value and "stylesheet" in value}
    )

    result["stylesheets"] = len(
        stylesheet_links
    )

    for stylesheet in stylesheet_links:

        href = stylesheet.get("href")

        if not href:
            continue

        absolute_url = urljoin(
            response.url,
            href
        )

        if is_external_url(
            absolute_url,
            page_hostname
        ):
            result["external_stylesheets"] += 1

    # --------------------------------------------------
    # REQUEST URL RESOURCES
    #
    # Resources:
    # img
    # script
    # stylesheet
    # --------------------------------------------------

    total_resources = (
        result["images"]
        + result["scripts"]
        + result["stylesheets"]
    )

    external_resources = (
        result["external_images"]
        + result["external_scripts"]
        + result["external_stylesheets"]
    )

    result["total_resources"] = total_resources

    result["external_resources"] = (
        external_resources
    )

    result["internal_resources"] = max(
        total_resources - external_resources,
        0
    )

    if total_resources > 0:

        result["request_url_external_percentage"] = (
            external_resources
            / total_resources
            * 100
        )

    # --------------------------------------------------
    # LINKS IN TAGS
    #
    # meta / script / link tags
    # --------------------------------------------------

    tagged_resources = []

    tagged_resources.extend(
        soup.find_all("script")
    )

    tagged_resources.extend(
        soup.find_all("link")
    )

    tagged_resources.extend(
        soup.find_all("meta")
    )

    external_tagged_resources = 0

    valid_tagged_resources = 0

    for tag in tagged_resources:

        resource_url = (
            tag.get("src")
            or tag.get("href")
            or tag.get("content")
        )

        if not resource_url:
            continue

        absolute_url = urljoin(
            response.url,
            resource_url
        )

        parsed_resource = urlparse(
            absolute_url
        )

        resource_hostname = (
            parsed_resource.hostname or ""
        ).lower()

        if not resource_hostname:
            continue

        valid_tagged_resources += 1

        if resource_hostname != page_hostname:

            external_tagged_resources += 1

    if valid_tagged_resources > 0:

        result[
            "links_in_tags_external_percentage"
        ] = (
            external_tagged_resources
            / valid_tagged_resources
            * 100
        )

    # --------------------------------------------------
    # IFRAME
    # --------------------------------------------------

    iframes = soup.find_all("iframe")

    result["iframe_count"] = len(iframes)

    # --------------------------------------------------
    # FAVICON
    # --------------------------------------------------

    favicon_selectors = [
        {"rel": "icon"},
        {"rel": "shortcut icon"}
    ]

    for selector in favicon_selectors:

        favicon = soup.find(
            "link",
            attrs=selector
        )

        if favicon:

            result["favicon_present"] = True
            break

    # --------------------------------------------------
    # ONMOUSEOVER
    # --------------------------------------------------

    for element in soup.find_all():

        if element.has_attr("onmouseover"):

            result["onmouseover_present"] = True
            break

    # --------------------------------------------------
    # RIGHT CLICK BLOCKING
    #
    # More specific than simply searching
    # for "return false".
    # --------------------------------------------------

    page_html_lower = response.text.lower()

    rightclick_patterns = [
        "oncontextmenu",
        "contextmenu",
        "event.button == 2",
        "event.button==2",
        "event.which == 3",
        "event.which==3"
    ]

    for pattern in rightclick_patterns:

        if pattern in page_html_lower:

            result["rightclick_blocking"] = True
            break

    # --------------------------------------------------
    # POPUP BEHAVIOR
    # --------------------------------------------------

    popup_patterns = [
        "window.open(",
        "window.open (",
        "showmodaldialog"
    ]

    for pattern in popup_patterns:

        if pattern in page_html_lower:

            result["popup_behavior"] = True
            break

    # --------------------------------------------------
    # HIDDEN ELEMENTS
    # --------------------------------------------------

    hidden_elements = soup.find_all(
        attrs={"type": "hidden"}
    )

    result["hidden_elements"] = len(
        hidden_elements
    )

    # --------------------------------------------------
    # SUSPICIOUS JAVASCRIPT
    #
    # This is only an indicator.
    # It must NOT independently classify
    # a website as phishing.
    # --------------------------------------------------

    suspicious_js_patterns = [
        "eval(",
        "unescape(",
        "fromcharcode(",
        "document.write("
    ]

    for pattern in suspicious_js_patterns:

        if pattern in page_html_lower:

            result["suspicious_javascript"] = True
            break

    return result