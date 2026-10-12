#!/usr/bin/env python3
"""
============================================================
 AI Security Model – FastAPI Inference Service
 PFE DevSecOps – EST Cybersécurité
 
 Endpoints:
   POST /classify        → classify a vulnerability
   POST /classify/batch  → classify multiple at once
   GET  /explain/{id}    → SHAP explanation
   GET  /model/info      → model metadata
   GET  /health          → health check
============================================================
"""

import os
import json
import time
import joblib
import numpy as np
from pathlib import Path
from datetime import datetime
from typing import Optional, TypedDict
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import shap

# ── Config ────────────────────────────────────────────────────
MODEL_DIR  = Path(os.getenv("MODEL_DIR", "./model"))
MODEL_PATH = MODEL_DIR / "model.pkl"
SHAP_PATH  = MODEL_DIR / "shap_explainer.pkl"
META_PATH  = MODEL_DIR / "metadata.json"

SEVERITY_MAP = {
    "CRITICAL": 4, "ERROR": 4,
    "HIGH": 3, "WARNING": 2,
    "MEDIUM": 2, "LOW": 1,
    "INFO": 0, "UNKNOWN": 0,
}

# ── Load model ────────────────────────────────────────────────
model     = None
explainer = None
metadata  = {}
cache: dict[str, list[float]] = {}  # Simple in-memory cache for SHAP explanations


class TopFeature(TypedDict):
    feature: str
    value: float
    shap_value: float


def default_cvss(severity_score: int) -> float:
    if severity_score == 4:
        return 9.0
    if severity_score == 3:
        return 7.0
    if severity_score == 2:
        return 5.0
    return 2.0


def confidence_level(score: float) -> str:
    delta = abs(score - 0.5)
    if delta > 0.3:
        return "high"
    if delta > 0.15:
        return "medium"
    return "low"


def risk_level(severity_score: int, score: float) -> str:
    if severity_score == 4 and score > 0.7:
        return "critical"
    if severity_score >= 3:
        return "high"
    if severity_score == 2:
        return "medium"
    return "low"

def load_model():
    global model, explainer, metadata
    if MODEL_PATH.exists():
        model     = joblib.load(MODEL_PATH)
        explainer = joblib.load(SHAP_PATH) if SHAP_PATH.exists() else None
        if META_PATH.exists():
            with open(META_PATH) as f:
                metadata = json.load(f)
        print(f"Model loaded (trained {metadata.get('trained_at', '?')})")
    else:
        print("No model found - using rule-based fallback")

load_model()

# ── FastAPI App ───────────────────────────────────────────────
app = FastAPI(
    title="DevSecOps AI Security Service",
    description="ML-powered vulnerability classifier with SHAP explainability",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Schemas ───────────────────────────────────────────────────
class VulnInput(BaseModel):
    id: str
    tool: str
    severity: str
    title: str
    description: Optional[str] = ""
    file: Optional[str] = ""
    line: Optional[int] = None
    cve: Optional[str] = None
    fix_version: Optional[str] = None
    cvss_score: Optional[float] = None
    days_since_found: Optional[int] = 0


class ClassifyResult(BaseModel):
    id: str
    label: str          # true_positive | false_positive
    score: float        # 0.0 → 1.0 (probability of being true positive)
    confidence: str     # high | medium | low
    risk_level: str     # critical | high | medium | low
    inference_ms: float
    filtered: bool      # True if AI considers this a false positive


# ── Feature extraction ────────────────────────────────────────
def extract_features(vuln: VulnInput) -> list[float]:
    sev  = SEVERITY_MAP.get(vuln.severity.upper(), 0)
    tool = vuln.tool.lower()

    title_lower = f"{vuln.title} {vuln.description or ''}".lower()
    injection  = int(any(k in title_lower for k in ["sql", "injection", "xss", "command", "path traversal"]))
    auth_pat   = int(any(k in title_lower for k in ["auth", "password", "credential", "token", "session"]))
    crypto_pat = int(any(k in title_lower for k in ["crypto", "cipher", "hash", "random", "tls", "ssl"]))

    file_path  = (vuln.file or "").lower()
    is_test    = int(any(k in file_path for k in ["test", "spec", "mock", "fixture", "__test__"]))
    has_sanit  = int(any(k in title_lower for k in ["sanitize", "escape", "encode", "validate", "filter"]))

    cvss = vuln.cvss_score if vuln.cvss_score is not None else default_cvss(sev)

    return [
        float(sev),                       # severity_score
        float("semgrep" in tool),         # tool_semgrep
        float("snyk" in tool),            # tool_snyk
        float("trivy" in tool),           # tool_trivy
        float("zap" in tool),             # tool_zap
        float(bool(vuln.cve)),            # has_cve
        float(bool(vuln.fix_version)),    # has_fix_available
        float(sev >= 3 and bool(vuln.cve)),  # exploit_public (proxy)
        float(cvss),                      # cvss_score
        min(sev / 4.0 + 0.2, 1.0),       # code_complexity
        0.5,                              # file_entropy (neutral)
        0.8 if sev >= 3 else 0.5,        # rule_confidence
        float(is_test),                   # is_test_file
        float(has_sanit),                 # has_sanitization
        float(injection),                 # injection_pattern
        float(auth_pat),                  # auth_pattern
        float(crypto_pat),                # crypto_pattern
        float(vuln.days_since_found or 0),  # days_since_vuln
        1.0,                              # affected_lines
    ]


def rule_based_fallback(vuln: VulnInput) -> tuple[float, str]:
    """Simple rule-based classifier when model not loaded."""
    sev = SEVERITY_MAP.get(vuln.severity.upper(), 0)
    score = sev / 4.0
    if vuln.cve:        score = min(score + 0.2, 1.0)
    if vuln.fix_version: score = min(score + 0.1, 1.0)
    label = "true_positive" if score > 0.5 else "false_positive"
    return round(score, 3), label


# ── Routes ────────────────────────────────────────────────────
@app.get("/health")
def health():
    return {
        "status": "ok",
        "model_loaded": model is not None,
        "trained_at": metadata.get("trained_at"),
        "fp_reduction": metadata.get("metrics", {}).get("fp_reduction_pct"),
    }


@app.get("/model/info")
def model_info():
    if not metadata:
        raise HTTPException(404, "Model not loaded")
    return metadata


@app.post("/classify", response_model=ClassifyResult)
def classify(vuln: VulnInput):
    t0 = time.time()

    if model is not None:
        features = extract_features(vuln)
        X = np.array(features).reshape(1, -1)
        score = float(model.predict_proba(X)[0][1])
        label = "true_positive" if score > 0.5 else "false_positive"
    else:
        score, label = rule_based_fallback(vuln)

    ms = round((time.time() - t0) * 1000, 2)

    confidence = confidence_level(score)
    sev = SEVERITY_MAP.get(vuln.severity.upper(), 0)
    risk = risk_level(sev, score)

    # Cache features for SHAP explanation
    cache[vuln.id] = extract_features(vuln)

    return ClassifyResult(
        id=vuln.id,
        label=label,
        score=round(score, 3),
        confidence=confidence,
        risk_level=risk,
        inference_ms=ms,
        filtered=(label == "false_positive"),
    )


@app.post("/classify/batch")
def classify_batch(vulns: list[VulnInput]):
    results = []
    filtered = 0
    for v in vulns:
        r = classify(v)
        results.append(r)
        if r.filtered:
            filtered += 1

    fp_rate = round(filtered / len(vulns) * 100, 1) if vulns else 0
    return {
        "total": len(vulns),
        "filtered_fps": filtered,
        "fp_reduction_pct": fp_rate,
        "results": results,
    }


@app.get("/explain/{vuln_id}")
def explain(vuln_id: str):
    if explainer is None:
        raise HTTPException(503, "SHAP explainer not available")

    features = cache.get(vuln_id)
    if not features:
        raise HTTPException(404, f"No cached features for vuln_id={vuln_id}. Call /classify first.")

    FEATURE_NAMES = [
        "severity_score", "tool_semgrep", "tool_snyk", "tool_trivy", "tool_zap",
        "has_cve", "has_fix_available", "exploit_public", "cvss_score",
        "code_complexity", "file_entropy", "rule_confidence", "is_test_file",
        "has_sanitization", "injection_pattern", "auth_pattern", "crypto_pattern",
        "days_since_vuln", "affected_lines",
    ]

    X = np.array(features).reshape(1, -1)
    shap_vals = explainer.shap_values(X)

    # For binary classification, take class 1 (true_positive)
    vals = shap_vals[1][0] if isinstance(shap_vals, list) else shap_vals[0]
    shap_contribs = np.asarray(vals, dtype=float).ravel()
    base = float(explainer.expected_value[1] if isinstance(explainer.expected_value, (list, np.ndarray)) else explainer.expected_value)

    top_features: list[TopFeature] = sorted(
        [
            TopFeature(feature=n, value=v, shap_value=float(s))
            for n, v, s in zip(FEATURE_NAMES, features, shap_contribs)
        ],
        key=lambda x: abs(x["shap_value"]),
        reverse=True,
    )[:8]

    score = features[0] / 4.0  # normalized severity as proxy
    shap_sum = sum(tf["shap_value"] for tf in top_features)

    # Human-readable summary
    top = top_features[0]["feature"] if top_features else "severity"
    summary = (
        f"The most influential factor is '{top}'. "
        f"{'High severity and public CVE increase the true positive probability.' if score > 0.5 else 'Low confidence and test file context reduce the true positive probability.'}"
    )

    return {
        "vuln_id": vuln_id,
        "explanation": {
            "decision": "true_positive" if shap_sum > 0 else "false_positive",
            "confidence": round(abs(shap_sum), 3),
            "base_value": round(base, 3),
            "top_features": top_features,
            "summary": summary,
        }
    }