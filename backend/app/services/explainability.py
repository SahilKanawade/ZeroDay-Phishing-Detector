import joblib
from pathlib import Path


# ==========================================================
# LOAD MODEL
# ==========================================================

BASE_DIR = Path(__file__).resolve().parents[3]

MODEL_PATH = (
    BASE_DIR
    / "ml"
    / "models"
    / "phishing_model.pkl"
)

model = joblib.load(MODEL_PATH)


# ==========================================================
# MODEL FEATURES
# ==========================================================

MODEL_FEATURES = [
    "having_ip_address",
    "url_length",
    "shortining_service",
    "having_at_symbol",
    "double_slash_redirecting",
    "prefix_suffix",
    "having_sub_domain",
    "sslfinal_state",
    "domain_registration_length",
    "favicon",
    "port",
    "https_token",
    "request_url",
    "url_of_anchor",
    "links_in_tags",
    "sfh",
    "submitting_to_email",
    "abnormal_url",
    "redirect",
    "on_mouseover",
    "rightclick",
    "popupwindow",
    "iframe",
    "age_of_domain",
    "dnsrecord",
    "web_traffic",
    "page_rank",
    "google_index",
    "links_pointing_to_page",
    "statistical_report",
]


# ==========================================================
# HUMAN-READABLE FEATURE DESCRIPTIONS
# ==========================================================

FEATURE_DESCRIPTIONS = {

    "having_ip_address":
        "Whether the URL uses an IP address instead of a domain.",

    "url_length":
        "URL length category.",

    "shortining_service":
        "Whether a URL shortening service was detected.",

    "having_at_symbol":
        "Whether an @ symbol is present in the URL.",

    "double_slash_redirecting":
        "Whether a suspicious double-slash redirect pattern exists.",

    "prefix_suffix":
        "Whether a hyphen is present in the domain.",

    "having_sub_domain":
        "Subdomain structure of the hostname.",

    "sslfinal_state":
        "Whether HTTPS is present.",

    "domain_registration_length":
        "Domain registration duration.",

    "favicon":
        "Whether a webpage favicon was detected.",

    "port":
        "Port configuration of the URL.",

    "https_token":
        "Whether an HTTPS-related token appears in the hostname.",

    "request_url":
        "External resource percentage on the webpage.",

    "url_of_anchor":
        "External anchor-link percentage.",

    "links_in_tags":
        "External links found inside HTML tags.",

    "sfh":
        "Form submission destination.",

    "submitting_to_email":
        "Whether form information is submitted through email.",

    "abnormal_url":
        "Whether an abnormal URL characteristic was detected.",

    "redirect":
        "Whether URL redirection was detected.",

    "on_mouseover":
        "Whether suspicious mouseover behavior was detected.",

    "rightclick":
        "Whether right-click blocking was detected.",

    "popupwindow":
        "Whether popup behavior was detected.",

    "iframe":
        "Whether an iframe was detected.",

    "age_of_domain":
        "Age of the domain.",

    "dnsrecord":
        "Whether a DNS record was detected.",

    "web_traffic":
        "Website traffic information.",

    "page_rank":
        "Page ranking information.",

    "google_index":
        "Whether the page is indexed by Google.",

    "links_pointing_to_page":
        "Number or category of links pointing to the page.",

    "statistical_report":
        "Statistical reputation information.",
}


# ==========================================================
# EXPLAIN PREDICTION
# ==========================================================

def explain_prediction(
    url_features,
    domain_features,
    html_features,
    prediction,
    threat_intelligence,
    model_features
):

    evidence = []

    positive_indicators = []

    unavailable_features = []

    warnings = []


    # ======================================================
    # 1. URL EVIDENCE
    # ======================================================

    suspicious_keywords = url_features.get(
        "suspicious_keywords",
        []
    )

    if suspicious_keywords:

        evidence.append({
            "category": "URL",
            "indicator": "Suspicious keywords",
            "value": suspicious_keywords,
            "explanation":
                "Credential, account or verification-related "
                "keywords were detected in the URL."
        })


    if url_features.get(
        "prefix_suffix"
    ) == -1:

        evidence.append({
            "category": "URL",
            "indicator": "Hyphenated domain",
            "value": url_features.get(
                "hyphen_count",
                0
            ),
            "explanation":
                "The domain contains one or more hyphens."
        })


    if url_features.get(
        "having_ip_address"
    ) == -1:

        evidence.append({
            "category": "URL",
            "indicator": "IP-based URL",
            "value": True,
            "explanation":
                "The URL uses an IP address instead of a domain name."
        })


    if url_features.get(
        "having_at_symbol"
    ) == -1:

        evidence.append({
            "category": "URL",
            "indicator": "@ symbol",
            "value": True,
            "explanation":
                "An @ symbol was detected in the URL."
        })


    if url_features.get(
        "shortining_service"
    ) == -1:

        evidence.append({
            "category": "URL",
            "indicator": "URL shortening",
            "value": True,
            "explanation":
                "A URL shortening service was detected."
        })


    if url_features.get(
        "having_sub_domain"
    ) == -1:

        evidence.append({
            "category": "URL",
            "indicator": "Multiple subdomains",
            "value": True,
            "explanation":
                "Multiple subdomains were detected."
        })


    # ======================================================
    # 2. POSITIVE URL INDICATORS
    # ======================================================

    if url_features.get(
        "https"
    ) == 1:

        positive_indicators.append({
            "category": "URL",
            "indicator": "HTTPS",
            "explanation":
                "HTTPS is enabled for the URL. "
                "HTTPS provides encryption but does not by itself "
                "prove that a website is trustworthy."
        })


    if url_features.get(
        "having_at_symbol"
    ) != -1:

        positive_indicators.append({
            "category": "URL",
            "indicator": "No @ symbol",
            "explanation":
                "No @ symbol was detected in the URL."
        })


    if url_features.get(
        "shortining_service"
    ) != -1:

        positive_indicators.append({
            "category": "URL",
            "indicator": "No URL shortening",
            "explanation":
                "No known URL-shortening indicator was detected."
        })


    # ======================================================
    # 3. DOMAIN / DNS EVIDENCE
    # ======================================================

    if domain_features.get(
        "domain_exists"
    ) is False:

        evidence.append({
            "category": "DOMAIN",
            "indicator": "DNS resolution failure",
            "value": False,
            "explanation":
                "The hostname could not be resolved through DNS."
        })

        warnings.append(
            "DNS resolution failed, so some domain and webpage "
            "information could not be evaluated."
        )

    elif domain_features.get(
        "dns_record"
    ):

        positive_indicators.append({
            "category": "DOMAIN",
            "indicator": "DNS record detected",
            "explanation":
                "The hostname successfully returned a DNS record."
        })


    # ======================================================
    # 4. HTML EVIDENCE
    # ======================================================

    page_reachable = html_features.get(
        "page_reachable",
        False
    )


    if not page_reachable:

        unavailable_features.extend([
            "favicon",
            "request_url",
            "url_of_anchor",
            "links_in_tags",
            "sfh",
            "submitting_to_email",
            "redirect",
            "on_mouseover",
            "rightclick",
            "popupwindow",
            "iframe"
        ])

        warnings.append(
            "The webpage could not be fetched. "
            "HTML-based indicators are therefore unavailable."
        )

    else:

        # PASSWORD INPUT

        if html_features.get(
            "password_inputs",
            0
        ) > 0:

            evidence.append({
                "category": "HTML",
                "indicator": "Password input",
                "value": html_features.get(
                    "password_inputs"
                ),
                "explanation":
                    "The webpage contains a password input field."
            })


        # EXTERNAL FORM

        if html_features.get(
            "external_form_actions",
            0
        ) > 0:

            evidence.append({
                "category": "HTML",
                "indicator": "External form submission",
                "value": html_features.get(
                    "external_form_actions"
                ),
                "explanation":
                    "A form submits information to an external domain."
            })


        # EMAIL FORM

        if html_features.get(
            "email_form_actions",
            0
        ) > 0:

            evidence.append({
                "category": "HTML",
                "indicator": "Email form submission",
                "value": html_features.get(
                    "email_form_actions"
                ),
                "explanation":
                    "A form submits information through an email action."
            })


        # IFRAME

        if html_features.get(
            "iframe_count",
            0
        ) > 0:

            evidence.append({
                "category": "HTML",
                "indicator": "Iframe",
                "value": html_features.get(
                    "iframe_count"
                ),
                "explanation":
                    "The webpage contains one or more iframes."
            })


        # JAVASCRIPT

        if html_features.get(
            "suspicious_javascript",
            False
        ):

            evidence.append({
                "category": "HTML",
                "indicator": "Suspicious JavaScript",
                "value": True,
                "explanation":
                    "Suspicious JavaScript patterns were detected."
            })


        # MOUSEOVER

        if html_features.get(
            "onmouseover_present",
            False
        ):

            evidence.append({
                "category": "HTML",
                "indicator": "Mouseover behavior",
                "value": True,
                "explanation":
                    "Mouseover event behavior was detected."
            })


        # RIGHT CLICK

        if html_features.get(
            "rightclick_blocking",
            False
        ):

            evidence.append({
                "category": "HTML",
                "indicator": "Right-click blocking",
                "value": True,
                "explanation":
                    "The webpage attempts to block right-click behavior."
            })


    # ======================================================
    # 5. THREAT INTELLIGENCE
    # ======================================================

    threat_score = threat_intelligence.get(
        "threat_score",
        0
    )

    threat_level = threat_intelligence.get(
        "threat_level",
        "low"
    )

    threat_indicators = threat_intelligence.get(
        "threat_indicators",
        []
    )


    if threat_score > 0:

        evidence.append({
            "category": "THREAT INTELLIGENCE",
            "indicator": "Threat score",
            "value": threat_score,
            "explanation":
                f"Local threat indicators produced a score of "
                f"{threat_score}/100."
        })


    for indicator in threat_indicators:

        if indicator.startswith(
            "HTTPS is present"
        ):
            continue

        evidence.append({
            "category": "THREAT INTELLIGENCE",
            "indicator": indicator,
            "value": True,
            "explanation":
                "This indicator contributed to the local "
                "threat-intelligence assessment."
        })


    # ======================================================
    # 6. MACHINE LEARNING RESULT
    # ======================================================

    ml_prediction = prediction.get(
        "prediction"
    )

    ml_confidence = prediction.get(
        "confidence"
    )


    if ml_prediction == -1:

        ml_label = "phishing"

    else:

        ml_label = "legitimate"


    # ======================================================
    # 7. GLOBAL RANDOM FOREST IMPORTANCE
    # ======================================================

    global_feature_importance = []


    if hasattr(
        model,
        "feature_importances_"
    ):

        importances = model.feature_importances_


        for feature, importance in zip(
            MODEL_FEATURES,
            importances
        ):

            global_feature_importance.append({

                "feature": feature,

                "description":
                    FEATURE_DESCRIPTIONS.get(
                        feature,
                        "Model feature."
                    ),

                "importance":
                    round(
                        float(importance),
                        4
                    ),

                "current_value":
                    model_features.get(
                        feature,
                        None
                    )
            })


        global_feature_importance.sort(
            key=lambda x: x["importance"],
            reverse=True
        )


        global_feature_importance = (
            global_feature_importance[:10]
        )


    # ======================================================
    # 8. SUMMARY
    # ======================================================

    if threat_level == "high":

        summary = (
            "High-risk indicators were detected."
        )

    elif threat_level == "medium":

        summary = (
            "Multiple suspicious indicators were detected."
        )

    elif evidence:

        summary = (
            "Some potentially suspicious indicators were detected."
        )

    else:

        summary = (
            "No major suspicious indicators were detected "
            "by the available analysis layers."
        )


    # ======================================================
    # 9. FINAL XAI RESPONSE
    # ======================================================

    return {

        "summary": summary,

        "observed_evidence": evidence,

        "positive_indicators": positive_indicators,

        "unavailable_features": unavailable_features,

        "ml_explanation": {

            "prediction": ml_label,

            "confidence": ml_confidence,

            "note":
                "The confidence value is the Random Forest "
                "prediction probability and should not be "
                "interpreted as a guaranteed probability of "
                "correctness."
        },

        "threat_intelligence": {

            "score": threat_score,

            "level": threat_level
        },

        "global_model_feature_importance":
            global_feature_importance,

        "warnings": warnings
    }