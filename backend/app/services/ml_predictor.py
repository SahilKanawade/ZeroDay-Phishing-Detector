import joblib
import pandas as pd

from pathlib import Path


# ============================================================
# LOCATE TRAINED MODEL
# ============================================================

BASE_DIR = Path(__file__).resolve().parents[3]

MODEL_PATH = BASE_DIR / "ml" / "models" / "phishing_model.pkl"


# ============================================================
# LOAD MODEL
# ============================================================

model = joblib.load(MODEL_PATH)


# ============================================================
# UCI MODEL FEATURES
# ============================================================

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


# ============================================================
# PREDICT PHISHING
# ============================================================

def predict_phishing(features: dict):

    # --------------------------------------------------------
    # Create a row containing all 30 model features
    # --------------------------------------------------------

    row = {}

    for feature in MODEL_FEATURES:
        row[feature] = 0


    # ========================================================
    # URL-BASED FEATURES
    # ========================================================

    row["having_ip_address"] = features.get(
        "having_ip_address",
        0
    )

    row["url_length"] = features.get(
        "url_length",
        0
    )

    row["shortining_service"] = features.get(
        "shortining_service",
        0
    )

    row["having_at_symbol"] = features.get(
        "having_at_symbol",
        0
    )

    row["double_slash_redirecting"] = features.get(
        "double_slash_redirecting",
        0
    )

    row["prefix_suffix"] = features.get(
        "prefix_suffix",
        0
    )

    row["having_sub_domain"] = features.get(
        "having_sub_domain",
        0
    )

    row["sslfinal_state"] = features.get(
        "sslfinal_state",
        0
    )

    row["port"] = features.get(
        "port",
        0
    )

    row["https_token"] = features.get(
        "https_token",
        0
    )

    row["request_url"] = features.get(
        "request_url",
        0
    )

    row["abnormal_url"] = features.get(
        "abnormal_url",
        0
    )


    # ========================================================
    # FEATURES NOT YET IMPLEMENTED
    # ========================================================
    #
    # These features require webpage, DNS, domain reputation,
    # HTML, WHOIS, or external intelligence analysis.
    #
    # They are currently kept as 0 until those analysis layers
    # are implemented.
    #
    # DO NOT interpret the current model prediction as final
    # production-level accuracy.
    # ========================================================

    row["domain_registration_length"] = features.get(
        "domain_registration_length",
        0
    )

    row["favicon"] = features.get(
        "favicon",
        0
    )

    row["url_of_anchor"] = features.get(
        "url_of_anchor",
        0
    )

    row["links_in_tags"] = features.get(
        "links_in_tags",
        0
    )

    row["sfh"] = features.get(
        "sfh",
        0
    )

    row["submitting_to_email"] = features.get(
        "submitting_to_email",
        0
    )

    row["redirect"] = features.get(
        "redirect",
        0
    )

    row["on_mouseover"] = features.get(
        "on_mouseover",
        0
    )

    row["rightclick"] = features.get(
        "rightclick",
        0
    )

    row["popupwindow"] = features.get(
        "popupwindow",
        0
    )

    row["iframe"] = features.get(
        "iframe",
        0
    )

    row["age_of_domain"] = features.get(
        "age_of_domain",
        0
    )

    row["dnsrecord"] = features.get(
        "dnsrecord",
        0
    )

    row["web_traffic"] = features.get(
        "web_traffic",
        0
    )

    row["page_rank"] = features.get(
        "page_rank",
        0
    )

    row["google_index"] = features.get(
        "google_index",
        0
    )

    row["links_pointing_to_page"] = features.get(
        "links_pointing_to_page",
        0
    )

    row["statistical_report"] = features.get(
        "statistical_report",
        0
    )


    # ========================================================
    # CREATE DATAFRAME
    # ========================================================

    input_data = pd.DataFrame(
        [[row[feature] for feature in MODEL_FEATURES]],
        columns=MODEL_FEATURES
    )


    # ========================================================
    # MODEL PREDICTION
    # ========================================================

    prediction = model.predict(input_data)[0]


    # ========================================================
    # MODEL PROBABILITY
    # ========================================================

    probability = None

    if hasattr(model, "predict_proba"):

        probabilities = model.predict_proba(input_data)[0]

        probability = float(max(probabilities))


    # ========================================================
    # CONVERT NUMPY INTEGER
    # ========================================================

    prediction = int(prediction)


    # ========================================================
    # UCI LABEL MAPPING
    #
    # -1 = phishing
    #  1 = legitimate
    # ========================================================

    if prediction == -1:

        label = "phishing"

    else:

        label = "legitimate"


    # ========================================================
    # RETURN RESULT
    # ========================================================

    return {
        "prediction": prediction,
        "label": label,
        "confidence": probability
    }