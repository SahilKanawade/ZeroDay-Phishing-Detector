def calculate_risk(
    url_features,
    domain_features,
    html_features,
    prediction,
    threat_intelligence
):
    """
    Hybrid risk engine.

    Combines:
    - URL analysis
    - DNS/domain analysis
    - HTML analysis
    - Machine learning prediction
    - Threat intelligence

    Returns an explainable risk assessment.
    """

    score = 0

    reasons = []

    warnings = []


    # ==========================================================
    # 1. URL ANALYSIS
    # ==========================================================

    suspicious_keywords = url_features.get(
        "suspicious_keywords",
        []
    )

    keyword_count = len(
        suspicious_keywords
    )


    if keyword_count >= 3:

        score += 20

        reasons.append(
            "Multiple suspicious keywords detected in URL "
            f"({', '.join(suspicious_keywords)})"
        )

    elif keyword_count > 0:

        score += 10

        reasons.append(
            "Suspicious keyword detected in URL "
            f"({', '.join(suspicious_keywords)})"
        )


    if url_features.get(
        "having_ip_address"
    ) == -1:

        score += 15

        reasons.append(
            "URL uses an IP address instead of a normal domain"
        )


    if url_features.get(
        "url_length"
    ) == -1:

        score += 10

        reasons.append(
            "URL is unusually long"
        )


    if url_features.get(
        "shortining_service"
    ) == -1:

        score += 10

        reasons.append(
            "URL shortening service detected"
        )


    if url_features.get(
        "having_at_symbol"
    ) == -1:

        score += 15

        reasons.append(
            "@ symbol detected in URL"
        )


    if url_features.get(
        "double_slash_redirecting"
    ) == -1:

        score += 10

        reasons.append(
            "Suspicious double-slash redirect pattern detected"
        )


    if url_features.get(
        "prefix_suffix"
    ) == -1:

        score += 10

        reasons.append(
            "Hyphen detected in domain name"
        )


    if url_features.get(
        "having_sub_domain"
    ) == -1:

        score += 10

        reasons.append(
            "Multiple subdomains detected"
        )


    if url_features.get(
        "https_token"
    ) == -1:

        score += 10

        reasons.append(
            "HTTPS token detected inside domain name"
        )


    # ==========================================================
    # 2. DNS / DOMAIN ANALYSIS
    # ==========================================================

    domain_exists = domain_features.get(
        "domain_exists"
    )

    dns_record = domain_features.get(
        "dns_record"
    )


    if domain_exists is False:

        score += 20

        reasons.append(
            "Domain could not be resolved through DNS"
        )

    elif dns_record is False:

        score += 15

        reasons.append(
            "No valid DNS record detected"
        )


    # ==========================================================
    # 3. HTML ANALYSIS
    # ==========================================================

    page_reachable = html_features.get(
        "page_reachable",
        False
    )


    if not page_reachable:

        warnings.append(
            "Webpage could not be fetched; "
            "HTML-based indicators are unavailable"
        )

    else:

        # ------------------------------------------------------
        # PASSWORD INPUT
        # ------------------------------------------------------

        password_inputs = html_features.get(
            "password_inputs",
            0
        )


        if password_inputs > 0:

            score += 10

            reasons.append(
                "Password input field detected"
            )


        # ------------------------------------------------------
        # EXTERNAL FORM
        # ------------------------------------------------------

        external_forms = html_features.get(
            "external_form_actions",
            0
        )


        if external_forms > 0:

            score += 15

            reasons.append(
                "Form submits data to an external domain"
            )


        # ------------------------------------------------------
        # EMAIL FORM
        # ------------------------------------------------------

        email_forms = html_features.get(
            "email_form_actions",
            0
        )


        if email_forms > 0:

            score += 15

            reasons.append(
                "Form submits information through email"
            )


        # ------------------------------------------------------
        # IFRAME
        # ------------------------------------------------------

        iframe_count = html_features.get(
            "iframe_count",
            0
        )


        if iframe_count > 0:

            score += 10

            reasons.append(
                "Iframe detected on webpage"
            )


        # ------------------------------------------------------
        # ONMOUSEOVER
        # ------------------------------------------------------

        if html_features.get(
            "onmouseover_present",
            False
        ):

            score += 10

            reasons.append(
                "Suspicious onmouseover behavior detected"
            )


        # ------------------------------------------------------
        # RIGHT CLICK
        # ------------------------------------------------------

        if html_features.get(
            "rightclick_blocking",
            False
        ):

            score += 10

            reasons.append(
                "Right-click blocking behavior detected"
            )


        # ------------------------------------------------------
        # POPUP
        # ------------------------------------------------------

        if html_features.get(
            "popup_behavior",
            False
        ):

            score += 10

            reasons.append(
                "Popup behavior detected"
            )


        # ------------------------------------------------------
        # SUSPICIOUS JAVASCRIPT
        # ------------------------------------------------------

        if html_features.get(
            "suspicious_javascript",
            False
        ):

            score += 10

            reasons.append(
                "Suspicious JavaScript patterns detected"
            )


    # ==========================================================
    # 4. THREAT INTELLIGENCE
    # ==========================================================

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


    # Add a limited contribution from threat intelligence.
    #
    # The threat engine has its own score, so we do not simply
    # add the complete threat score. This prevents double-counting
    # the same URL indicators.

    if threat_score >= 50:

        score += 20

        reasons.append(
            "Threat intelligence layer reports a high indicator score"
        )

    elif threat_score >= 25:

        score += 10

        reasons.append(
            "Threat intelligence layer reports a medium indicator score"
        )

    elif threat_score > 0:

        score += 5

        reasons.append(
            "Threat intelligence layer detected suspicious indicators"
        )


    # Add unique threat indicators as explanations.

    for indicator in threat_indicators:

        if indicator not in reasons:

            # Do not treat HTTPS itself as a suspicious reason.
            if indicator.startswith(
                "HTTPS is present"
            ):
                continue

            reasons.append(
                f"Threat intelligence: {indicator}"
            )


    # ==========================================================
    # 5. MACHINE LEARNING RESULT
    # ==========================================================

    ml_prediction = prediction.get(
        "prediction"
    )

    ml_confidence = prediction.get(
        "confidence"
    )


    if ml_prediction == -1:

        score += 25

        reasons.append(
            "Machine learning model classified the URL as phishing"
        )


    elif ml_prediction == 1:

        if ml_confidence is not None:

            warnings.append(
                "Machine learning model classified the URL "
                f"as legitimate with {ml_confidence:.1%} confidence"
            )

        else:

            warnings.append(
                "Machine learning model classified the URL as legitimate"
            )


    # ==========================================================
    # 6. LIMIT SCORE
    # ==========================================================

    score = min(
        max(
            score,
            0
        ),
        100
    )


    # ==========================================================
    # 7. RISK LEVEL
    # ==========================================================

    if score >= 70:

        risk_level = "high"

    elif score >= 40:

        risk_level = "medium"

    else:

        risk_level = "low"


    # ==========================================================
    # 8. FINAL RESULT
    # ==========================================================

    return {
        "risk_score": score,
        "risk_level": risk_level,

        "reasons": reasons,

        "warnings": warnings,

        "ml_prediction": ml_prediction,

        "ml_confidence": ml_confidence,

        "threat_score": threat_score,

        "threat_level": threat_level
    }