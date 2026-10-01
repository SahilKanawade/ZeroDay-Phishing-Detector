from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from backend.app.services.url_analyzer import analyze_url
from backend.app.services.domain_analyzer import analyze_domain
from backend.app.services.html_analyzer import analyze_html
from backend.app.services.feature_fusion import build_model_features
from backend.app.services.ml_predictor import predict_phishing
from backend.app.services.risk_engine import calculate_risk
from backend.app.services.threat_intelligence import (
    analyze_threat_intelligence
)
from backend.app.services.explainability import (
    explain_prediction
)


# ---------------------------------------------------------
# FastAPI Application
# ---------------------------------------------------------

app = FastAPI(
    title="Zero-Day Phishing Detector",
    description="AI-powered phishing website detection API",
    version="1.0.0"
)


# ---------------------------------------------------------
# CORS Configuration
# ---------------------------------------------------------
# Allows the React frontend running on Vite to communicate
# with the FastAPI backend.

import os

FRONTEND_URL = os.getenv("FRONTEND_URL", "").strip()

ALLOWED_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]

if FRONTEND_URL:
    ALLOWED_ORIGINS.append(FRONTEND_URL)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------
# Request Model
# ---------------------------------------------------------

class URLRequest(BaseModel):
    url: str


# ---------------------------------------------------------
# Root Endpoint
# ---------------------------------------------------------

@app.get("/")
def root():
    return {
        "project": "Zero-Day Phishing Detector",
        "status": "running"
    }


# ---------------------------------------------------------
# Health Check
# ---------------------------------------------------------

@app.get("/health")
def health():
    return {
        "status": "healthy"
    }


# ---------------------------------------------------------
# Main URL Analysis Endpoint
# ---------------------------------------------------------

@app.post("/analyze-url")
def analyze_website(request: URLRequest):

    # -----------------------------------------------------
    # 1. URL ANALYSIS
    # -----------------------------------------------------

    url_features = analyze_url(
        request.url
    )


    # -----------------------------------------------------
    # 2. DOMAIN / DNS ANALYSIS
    # -----------------------------------------------------

    domain_features = analyze_domain(
        request.url
    )


    # -----------------------------------------------------
    # 3. HTML / WEBPAGE ANALYSIS
    # -----------------------------------------------------

    html_features = analyze_html(
        request.url
    )


    # -----------------------------------------------------
    # 4. FEATURE FUSION
    # -----------------------------------------------------

    model_features = build_model_features(
        url_features,
        domain_features,
        html_features
    )


    # -----------------------------------------------------
    # 5. MACHINE LEARNING PREDICTION
    # -----------------------------------------------------

    prediction = predict_phishing(
        model_features
    )


    # -----------------------------------------------------
    # 6. THREAT INTELLIGENCE
    # -----------------------------------------------------

    threat_intelligence = analyze_threat_intelligence(
        request.url
    )


    # -----------------------------------------------------
    # 7. HYBRID RISK ANALYSIS
    # -----------------------------------------------------

    risk_assessment = calculate_risk(
        url_features,
        domain_features,
        html_features,
        prediction,
        threat_intelligence
    )


    # -----------------------------------------------------
    # 8. EXPLAINABLE AI
    # -----------------------------------------------------

    explanation = explain_prediction(
        url_features,
        domain_features,
        html_features,
        prediction,
        threat_intelligence,
        model_features
    )


    # -----------------------------------------------------
    # 9. FINAL API RESPONSE
    # -----------------------------------------------------

    return {
        "url": request.url,

        "url_analysis": url_features,

        "domain_analysis": domain_features,

        "html_analysis": html_features,

        "model_features": model_features,

        "prediction": prediction,

        "threat_intelligence": threat_intelligence,

        "risk_assessment": risk_assessment,

        "explanation": explanation
    }