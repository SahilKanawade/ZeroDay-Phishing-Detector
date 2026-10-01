import { useEffect, useState } from "react";
import "./index.css";

const API_URL = import.meta.env.VITE_API_URL || "http://127.0.0.1:8000";

function App() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [apiOnline, setApiOnline] = useState(false);

  // =========================================================
  // API HEALTH CHECK
  // =========================================================

  useEffect(() => {
    const checkApiHealth = async () => {
      try {
        const response = await fetch(`${API_URL}/health`);

        if (!response.ok) {
          throw new Error("API unavailable");
        }

        const data = await response.json();

        setApiOnline(data.status === "healthy");
      } catch {
        setApiOnline(false);
      }
    };

    checkApiHealth();

    const interval = setInterval(checkApiHealth, 10000);

    return () => clearInterval(interval);
  }, []);

  // =========================================================
  // ANALYZE URL
  // =========================================================

  const analyzeUrl = async () => {
    if (!url.trim()) {
      setError("Please enter a website URL.");
      return;
    }

    setLoading(true);
    setError("");
    setResult(null);

    try {
      const response = await fetch(`${API_URL}/analyze-url`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          url: url.trim(),
        }),
      });

      if (!response.ok) {
        throw new Error("Analysis request failed.");
      }

      const data = await response.json();

      setResult(data);
      setApiOnline(true);
    } catch {
      setApiOnline(false);

      setError(
        "Unable to connect to the detection server. Make sure the FastAPI backend is running."
      );
    } finally {
      setLoading(false);
    }
  };

  // =========================================================
  // RESULT VALUES
  // =========================================================

  const riskScore = result?.risk_assessment?.risk_score ?? 0;

  const riskLevel =
    result?.risk_assessment?.risk_level ?? "unknown";

  const riskClass =
    riskLevel === "high"
      ? "high"
      : riskLevel === "medium"
      ? "medium"
      : "low";

  const mlPrediction =
    result?.prediction?.label ||
    (result?.prediction?.prediction === -1
      ? "phishing"
      : result?.prediction?.prediction === 1
      ? "legitimate"
      : "unknown");

  const mlConfidence = result?.prediction?.confidence;

  return (
    <div className="app">

      {/* =====================================================
          TOP BAR
      ===================================================== */}

      <header className="topbar">

        <div className="brand">

          <div className="brand-icon">
            🛡
          </div>

          <div>
            <h1>Zero-Day Phishing Detector</h1>

            <p>
              Explainable AI Security Analysis
            </p>
          </div>

        </div>

        {/* REAL API STATUS */}

        <div
          className={`status ${
            apiOnline ? "online" : "offline"
          }`}
        >
          <span className="status-dot"></span>

          {apiOnline
            ? "API Online"
            : "API Offline"}
        </div>

      </header>


      {/* =====================================================
          MAIN CONTENT
      ===================================================== */}

      <main className="container">

        {/* ===================================================
            HERO
        =================================================== */}

        <section className="hero">

          <div className="hero-badge">
            AI-POWERED THREAT DETECTION
          </div>

          <h2>
            Detect phishing websites
            <span> before they deceive you.</span>
          </h2>

          <p>
            Analyze URL characteristics, domain reputation,
            webpage behavior, machine-learning predictions
            and threat indicators in real time.
          </p>


          {/* URL SCANNER */}

          <div className="scanner">

            <div className="input-wrapper">

              <span>🔗</span>

              <input
                type="text"
                placeholder="Enter website URL, e.g. https://example.com"
                value={url}
                onChange={(e) =>
                  setUrl(e.target.value)
                }
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    analyzeUrl();
                  }
                }}
              />

            </div>


            <button
              className="analyze-button"
              onClick={analyzeUrl}
              disabled={loading}
            >
              {loading
                ? "Analyzing..."
                : "🔍 Analyze Website"}
            </button>

          </div>


          {/* ERROR */}

          {error && (
            <div className="error-box">
              ⚠ {error}
            </div>
          )}

        </section>


        {/* ===================================================
            LOADING
        =================================================== */}

        {loading && (

          <section className="loading-card">

            <div className="loader"></div>

            <div>

              <h3>
                Analyzing website...
              </h3>

              <p>
                Running URL, DNS, webpage,
                ML and threat-intelligence analysis.
              </p>

            </div>

          </section>

        )}


        {/* ===================================================
            RESULTS
        =================================================== */}

        {result && !loading && (

          <>

            {/* RESULT HEADER */}

            <section className="result-header">

              <div>

                <p className="section-label">
                  SCAN RESULT
                </p>

                <h2>
                  Security Assessment
                </h2>

                <p className="scanned-url">
                  {result.url}
                </p>

              </div>


              <div
                className={`risk-badge ${riskClass}`}
              >
                {riskLevel.toUpperCase()} RISK
              </div>

            </section>


            {/* =================================================
                STAT CARDS
            ================================================= */}

            <section className="stats-grid">

              {/* RISK */}

              <div
                className={`stat-card risk-card ${riskClass}`}
              >

                <div className="stat-icon">
                  ⚠
                </div>

                <div>

                  <p>
                    Risk Score
                  </p>

                  <strong>
                    {riskScore}/100
                  </strong>

                  <span>
                    Hybrid risk engine
                  </span>

                </div>

              </div>


              {/* ML */}

              <div className="stat-card">

                <div className="stat-icon">
                  🤖
                </div>

                <div>

                  <p>
                    ML Prediction
                  </p>

                  <strong className="prediction">
                    {mlPrediction.toUpperCase()}
                  </strong>

                  <span>

                    {mlConfidence !== undefined
                      ? `${(
                          mlConfidence * 100
                        ).toFixed(1)}% model confidence`
                      : "Confidence unavailable"}

                  </span>

                </div>

              </div>


              {/* THREAT INTELLIGENCE */}

              <div className="stat-card">

                <div className="stat-icon">
                  🧠
                </div>

                <div>

                  <p>
                    Threat Intelligence
                  </p>

                  <strong>
                    {result.threat_intelligence
                      ?.threat_score ?? 0}
                    /100
                  </strong>

                  <span>

                    {(
                      result.threat_intelligence
                        ?.threat_level ||
                      "low"
                    ).toUpperCase()}{" "}
                    indicator level

                  </span>

                </div>

              </div>


              {/* DOMAIN */}

              <div className="stat-card">

                <div className="stat-icon">
                  🌐
                </div>

                <div>

                  <p>
                    Domain Status
                  </p>

                  <strong>

                    {result.domain_analysis
                      ?.domain_exists
                      ? "RESOLVED"
                      : "NOT FOUND"}

                  </strong>

                  <span>

                    {result.domain_analysis
                      ?.ip_address_count ?? 0}{" "}
                    IP address(es)

                  </span>

                </div>

              </div>

            </section>


            {/* =================================================
                ANALYSIS GRID
            ================================================= */}

            <section className="dashboard-grid">


              {/* URL ANALYSIS */}

              <div className="panel">

                <div className="panel-title">

                  <div>

                    <span className="panel-icon">
                      🔗
                    </span>

                    <h3>
                      URL Analysis
                    </h3>

                  </div>

                </div>


                <div className="detail-list">

                  <Detail
                    label="URL Length"
                    value={
                      result.url_analysis
                        ?.raw_url_length
                    }
                  />

                  <Detail
                    label="HTTPS"
                    value={
                      result.url_analysis
                        ?.https === 1
                        ? "Enabled"
                        : "Not detected"
                    }
                  />

                  <Detail
                    label="Hyphens"
                    value={
                      result.url_analysis
                        ?.hyphen_count
                    }
                  />

                  <Detail
                    label="Subdomains"
                    value={
                      result.url_analysis
                        ?.subdomain_count
                    }
                  />

                  <Detail
                    label="Suspicious Keywords"
                    value={
                      result.url_analysis
                        ?.suspicious_keywords
                        ?.length || 0
                    }
                  />

                </div>

              </div>


              {/* DOMAIN / DNS */}

              <div className="panel">

                <div className="panel-title">

                  <div>

                    <span className="panel-icon">
                      🌐
                    </span>

                    <h3>
                      Domain & DNS
                    </h3>

                  </div>

                </div>


                <div className="detail-list">

                  <Detail
                    label="Hostname"
                    value={
                      result.domain_analysis
                        ?.hostname ||
                      "Unknown"
                    }
                  />

                  <Detail
                    label="DNS Record"
                    value={
                      result.domain_analysis
                        ?.dns_record
                        ? "Detected"
                        : "Not detected"
                    }
                  />

                  <Detail
                    label="Domain Exists"
                    value={
                      result.domain_analysis
                        ?.domain_exists
                        ? "Yes"
                        : "No"
                    }
                  />

                  <Detail
                    label="IP Addresses"
                    value={
                      result.domain_analysis
                        ?.ip_address_count ?? 0
                    }
                  />

                  <Detail
                    label="Page Reachable"
                    value={
                      result.html_analysis
                        ?.page_reachable
                        ? "Yes"
                        : "No"
                    }
                  />

                </div>

              </div>


              {/* THREAT INTELLIGENCE */}

              <div className="panel">

                <div className="panel-title">

                  <div>

                    <span className="panel-icon">
                      🛡
                    </span>

                    <h3>
                      Threat Intelligence
                    </h3>

                  </div>


                  <span
                    className={`mini-badge ${
                      result.threat_intelligence
                        ?.threat_level
                    }`}
                  >
                    {(
                      result.threat_intelligence
                        ?.threat_level ||
                      "low"
                    ).toUpperCase()}
                  </span>

                </div>


                <div className="threat-score">

                  <div className="score-circle">

                    <span>
                      {result.threat_intelligence
                        ?.threat_score ?? 0}
                    </span>

                    <small>
                      /100
                    </small>

                  </div>


                  <div>

                    <h4>
                      Local Threat Indicators
                    </h4>

                    <p>

                      {result.threat_intelligence
                        ?.suspicious_keyword_count ??
                        0}{" "}
                      suspicious keyword(s)
                      detected.

                    </p>

                  </div>

                </div>


                <div className="keyword-list">

                  {(
                    result.threat_intelligence
                      ?.suspicious_keywords ||
                    []
                  ).map((keyword) => (

                    <span key={keyword}>
                      {keyword}
                    </span>

                  ))}

                </div>

              </div>


              {/* MACHINE LEARNING */}

              <div className="panel">

                <div className="panel-title">

                  <div>

                    <span className="panel-icon">
                      🤖
                    </span>

                    <h3>
                      Machine Learning
                    </h3>

                  </div>

                </div>


                <div className="ml-result">

                  <div
                    className={`ml-indicator ${
                      mlPrediction ===
                      "phishing"
                        ? "danger"
                        : "safe"
                    }`}
                  >

                    {mlPrediction ===
                    "phishing"
                      ? "!"
                      : "✓"}

                  </div>


                  <div>

                    <h4>
                      {mlPrediction.toUpperCase()}
                    </h4>

                    <p>
                      Random Forest
                      classification result.
                    </p>


                    {mlConfidence !==
                      undefined && (

                      <div className="confidence-bar">

                        <div
                          style={{
                            width: `${
                              mlConfidence *
                              100
                            }%`,
                          }}
                        ></div>

                      </div>

                    )}

                  </div>

                </div>


                <div className="model-note">

                  Model confidence represents
                  the Random Forest prediction
                  probability and is not a
                  guaranteed probability of
                  correctness.

                </div>

              </div>

            </section>


            {/* =================================================
                EXPLAINABLE AI
            ================================================= */}

            <section className="panel evidence-panel">

              <div className="panel-title">

                <div>

                  <span className="panel-icon">
                    🧠
                  </span>

                  <div>

                    <h3>
                      Explainable AI
                    </h3>

                    <p>
                      Why the system produced
                      this assessment
                    </p>

                  </div>

                </div>

              </div>


              <div className="summary-box">

                <strong>

                  {result.explanation
                    ?.summary ||
                    "Analysis completed."}

                </strong>

              </div>


              <div className="evidence-grid">

                {(
                  result.explanation
                    ?.observed_evidence ||
                  []
                ).map(
                  (item, index) => (

                    <div
                      className="evidence-item"
                      key={index}
                    >

                      <div className="evidence-category">
                        {item.category}
                      </div>

                      <h4>
                        {item.indicator}
                      </h4>

                      <p>
                        {item.explanation}
                      </p>


                      {item.value !==
                        undefined && (

                        <div className="evidence-value">

                          {Array.isArray(
                            item.value
                          )
                            ? item.value.join(
                                ", "
                              )
                            : String(
                                item.value
                              )}

                        </div>

                      )}

                    </div>

                  )
                )}

              </div>

            </section>


            {/* =================================================
                POSITIVE + WARNINGS
            ================================================= */}

            <section className="two-column">


              {/* POSITIVE */}

              <div className="panel">

                <div className="panel-title">

                  <div>

                    <span className="panel-icon">
                      ✓
                    </span>

                    <h3>
                      Positive Indicators
                    </h3>

                  </div>

                </div>


                <div className="indicator-list positive">

                  {(
                    result.explanation
                      ?.positive_indicators ||
                    []
                  ).map(
                    (item, index) => (

                      <div key={index}>

                        <span>
                          ✓
                        </span>

                        <div>

                          <strong>
                            {item.indicator}
                          </strong>

                          <p>
                            {item.explanation}
                          </p>

                        </div>

                      </div>

                    )
                  )}

                </div>

              </div>


              {/* WARNINGS */}

              <div className="panel">

                <div className="panel-title">

                  <div>

                    <span className="panel-icon">
                      ⚠
                    </span>

                    <h3>
                      Warnings & Limitations
                    </h3>

                  </div>

                </div>


                <div className="indicator-list warning">

                  {(
                    result.explanation
                      ?.warnings ||
                    result.risk_assessment
                      ?.warnings ||
                    []
                  ).map(
                    (warning, index) => (

                      <div key={index}>

                        <span>
                          !
                        </span>

                        <div>

                          <p>
                            {warning}
                          </p>

                        </div>

                      </div>

                    )
                  )}

                </div>


                {(
                  result.explanation
                    ?.unavailable_features ||
                  []
                ).length > 0 && (

                  <div className="unavailable">

                    <strong>
                      Unavailable HTML features:
                    </strong>

                    <p>

                      {result.explanation
                        .unavailable_features
                        .join(", ")}

                    </p>

                  </div>

                )}

              </div>

            </section>


            {/* =================================================
                FEATURE IMPORTANCE
            ================================================= */}

            <section className="panel">

              <div className="panel-title">

                <div>

                  <span className="panel-icon">
                    📊
                  </span>

                  <div>

                    <h3>
                      Global Model Feature
                      Importance
                    </h3>

                    <p>
                      Top features used by
                      the trained Random Forest
                    </p>

                  </div>

                </div>

              </div>


              <div className="importance-list">

                {(
                  result.explanation
                    ?.global_model_feature_importance ||
                  []
                ).map((item) => (

                  <div
                    className="importance-item"
                    key={item.feature}
                  >

                    <div className="importance-header">

                      <strong>
                        {item.feature}
                      </strong>

                      <span>
                        {(
                          item.importance * 100
                        ).toFixed(2)}
                        %
                      </span>

                    </div>


                    <div className="importance-bar">

                      <div
                        style={{
                          width: `${Math.min(
                            item.importance *
                              100 *
                              2.5,
                            100
                          )}%`,
                        }}
                      ></div>

                    </div>


                    <p>
                      {item.description}
                    </p>

                  </div>

                ))}

              </div>

            </section>

          </>

        )}


        {/* ===================================================
            EMPTY STATE
        =================================================== */}

        {!result && !loading && (

          <section className="features">

            <div className="feature">

              <span>
                🔍
              </span>

              <h3>
                Multi-Layer Analysis
              </h3>

              <p>
                URL, DNS, webpage and
                threat indicators are
                analyzed together.
              </p>

            </div>


            <div className="feature">

              <span>
                🤖
              </span>

              <h3>
                Machine Learning
              </h3>

              <p>
                Random Forest classification
                helps identify suspicious
                websites.
              </p>

            </div>


            <div className="feature">

              <span>
                🧠
              </span>

              <h3>
                Explainable AI
              </h3>

              <p>
                Understand the evidence
                behind the security
                assessment.
              </p>

            </div>

          </section>

        )}

      </main>


      {/* =====================================================
          FOOTER
      ===================================================== */}

      <footer>

        <p>
          Zero-Day Phishing Detector •
          AI-powered cybersecurity research project
        </p>

        <p className="copyright">
          © 2026 Sahil Kanawade. All Rights Reserved.
        </p>

      </footer>

    </div>
  );
}


// ============================================================
// DETAIL COMPONENT
// ============================================================

function Detail({ label, value }) {
  return (
    <div className="detail-row">

      <span>
        {label}
      </span>

      <strong>
        {value ?? "N/A"}
      </strong>

    </div>
  );
}


export default App;