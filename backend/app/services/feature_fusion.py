def build_model_features(
    url_features,
    domain_features,
    html_features
):
    """
    Combine URL, domain/DNS and HTML analysis
    into the 30 features expected by the trained model.

    Unknown/unavailable HTML features are represented as 0
    instead of being treated as legitimate or suspicious.
    """

    features = {}

    # ==========================================================
    # 1. URL FEATURES
    # ==========================================================

    features["having_ip_address"] = url_features.get(
        "having_ip_address", 0
    )

    features["url_length"] = url_features.get(
        "url_length", 0
    )

    features["shortining_service"] = url_features.get(
        "shortining_service", 0
    )

    features["having_at_symbol"] = url_features.get(
        "having_at_symbol", 0
    )

    features["double_slash_redirecting"] = url_features.get(
        "double_slash_redirecting", 0
    )

    features["prefix_suffix"] = url_features.get(
        "prefix_suffix", 0
    )

    features["having_sub_domain"] = url_features.get(
        "having_sub_domain", 0
    )

    features["sslfinal_state"] = url_features.get(
        "sslfinal_state", 0
    )

    features["port"] = url_features.get(
        "port", 0
    )

    features["https_token"] = url_features.get(
        "https_token", 0
    )

    features["abnormal_url"] = url_features.get(
        "abnormal_url", 0
    )


    # ==========================================================
    # 2. DNS / DOMAIN FEATURE
    # ==========================================================

    if domain_features.get("dns_record") is True:

        features["dnsrecord"] = 1

    elif domain_features.get("dns_record") is False:

        features["dnsrecord"] = -1

    else:

        features["dnsrecord"] = 0


    # ==========================================================
    # 3. CHECK WHETHER HTML PAGE WAS ACTUALLY ANALYZED
    # ==========================================================

    page_reachable = html_features.get(
        "page_reachable",
        False
    )


    # ==========================================================
    # 4. HTML FEATURES
    # ==========================================================

    if not page_reachable:

        # The webpage could not be fetched.
        # Therefore these properties are UNKNOWN,
        # not automatically legitimate or suspicious.

        features["favicon"] = 0

        features["request_url"] = 0

        features["url_of_anchor"] = 0

        features["links_in_tags"] = 0

        features["sfh"] = 0

        features["submitting_to_email"] = 0

        features["redirect"] = 0

        features["on_mouseover"] = 0

        features["rightclick"] = 0

        features["popupwindow"] = 0

        features["iframe"] = 0

    else:

        # ------------------------------------------------------
        # FAVICON
        # ------------------------------------------------------

        if html_features.get(
            "favicon_present",
            False
        ):

            features["favicon"] = 1

        else:

            features["favicon"] = -1


        # ------------------------------------------------------
        # REQUEST URL
        # ------------------------------------------------------

        external_resource_percentage = html_features.get(
            "request_url_external_percentage",
            0
        )

        if external_resource_percentage <= 22:

            features["request_url"] = 1

        elif external_resource_percentage <= 61:

            features["request_url"] = 0

        else:

            features["request_url"] = -1


        # ------------------------------------------------------
        # URL OF ANCHOR
        # ------------------------------------------------------

        anchor_percentage = html_features.get(
            "anchor_external_percentage",
            0
        )

        if anchor_percentage <= 31:

            features["url_of_anchor"] = 1

        elif anchor_percentage <= 67:

            features["url_of_anchor"] = 0

        else:

            features["url_of_anchor"] = -1


        # ------------------------------------------------------
        # LINKS IN TAGS
        # ------------------------------------------------------

        tag_percentage = html_features.get(
            "links_in_tags_external_percentage",
            0
        )

        if tag_percentage <= 17:

            features["links_in_tags"] = 1

        elif tag_percentage <= 81:

            features["links_in_tags"] = 0

        else:

            features["links_in_tags"] = -1


        # ------------------------------------------------------
        # SFH
        # ------------------------------------------------------

        if html_features.get(
            "external_form_actions",
            0
        ) > 0:

            features["sfh"] = -1

        elif html_features.get(
            "forms",
            0
        ) > 0:

            features["sfh"] = 1

        else:

            features["sfh"] = 0


        # ------------------------------------------------------
        # SUBMITTING TO EMAIL
        # ------------------------------------------------------

        if html_features.get(
            "email_form_actions",
            0
        ) > 0:

            features["submitting_to_email"] = -1

        else:

            features["submitting_to_email"] = 1


        # ------------------------------------------------------
        # REDIRECT
        # ------------------------------------------------------

        original_url = url_features.get(
            "normalized_url",
            ""
        )

        final_url = html_features.get(
            "final_url",
            ""
        )

        if original_url and final_url:

            if (
                original_url.rstrip("/")
                != final_url.rstrip("/")
            ):

                features["redirect"] = 1

            else:

                features["redirect"] = 0

        else:

            features["redirect"] = 0


        # ------------------------------------------------------
        # ON MOUSEOVER
        # ------------------------------------------------------

        if html_features.get(
            "onmouseover_present",
            False
        ):

            features["on_mouseover"] = -1

        else:

            features["on_mouseover"] = 1


        # ------------------------------------------------------
        # RIGHT CLICK
        # ------------------------------------------------------

        if html_features.get(
            "rightclick_blocking",
            False
        ):

            features["rightclick"] = -1

        else:

            features["rightclick"] = 1


        # ------------------------------------------------------
        # POPUP WINDOW
        # ------------------------------------------------------

        if html_features.get(
            "popup_behavior",
            False
        ):

            features["popupwindow"] = -1

        else:

            features["popupwindow"] = 1


        # ------------------------------------------------------
        # IFRAME
        # ------------------------------------------------------

        if html_features.get(
            "iframe_count",
            0
        ) > 0:

            features["iframe"] = -1

        else:

            features["iframe"] = 1


    # ==========================================================
    # 5. EXTERNAL INTELLIGENCE FEATURES
    # ==========================================================
    #
    # These features are not implemented yet.
    #
    # 0 means UNKNOWN / NOT AVAILABLE.
    #
    # They will be implemented in the next stage.
    # ==========================================================

    features["domain_registration_length"] = 0

    features["age_of_domain"] = 0

    features["web_traffic"] = 0

    features["page_rank"] = 0

    features["google_index"] = 0

    features["links_pointing_to_page"] = 0

    features["statistical_report"] = 0


    # ==========================================================
    # 6. RETURN FINAL 30-FEATURE VECTOR
    # ==========================================================

    return features