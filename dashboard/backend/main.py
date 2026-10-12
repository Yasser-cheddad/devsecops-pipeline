"""
Dashboard API – aggregates pipeline reports and proxies AI classify/explain.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Optional

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

REPORTS_DIR = Path(os.getenv("REPORTS_DIR", "./reports"))
AI_SERVICE_URL = os.getenv("AI_SERVICE_URL", "http://localhost:8001").rstrip("/")
STATIC_DIR = Path(os.getenv("STATIC_DIR", "./static"))

app = FastAPI(title="DevSecOps Dashboard API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "*").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def read_summary() -> dict:
    path = REPORTS_DIR / "dashboard-summary.json"
    if not path.exists():
        return {
            "generated_at": None,
            "pipeline": {},
            "gates": [],
            "ai": {},
            "cloud": {},
            "vulnerabilities": [],
            "counts": {"total": 0, "by_tool": {}, "by_severity": {}},
        }
    return json.loads(path.read_text(encoding="utf-8"))


class ClassifyBody(BaseModel):
    id: str
    tool: str
    severity: str
    title: str
    description: Optional[str] = ""
    file: Optional[str] = ""
    line: Optional[int] = None
    cve: Optional[str] = None
    fix_version: Optional[str] = None


@app.get("/api/health")
def health():
    ai_ok = False
    try:
        r = httpx.get(f"{AI_SERVICE_URL}/health", timeout=3.0)
        ai_ok = r.status_code == 200
    except httpx.HTTPError:
        pass
    return {
        "status": "ok",
        "reports_dir": str(REPORTS_DIR),
        "summary_exists": (REPORTS_DIR / "dashboard-summary.json").exists(),
        "ai_service": AI_SERVICE_URL,
        "ai_reachable": ai_ok,
    }


@app.get("/api/pipeline/status")
def pipeline_status():
    return read_summary()


@app.get("/api/vulnerabilities")
def list_vulnerabilities(
    tool: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
):
    data = read_summary()
    items = data.get("vulnerabilities", [])
    if tool:
        items = [v for v in items if v.get("tool") == tool]
    if severity:
        items = [v for v in items if str(v.get("severity", "")).upper() == severity.upper()]
    if status:
        items = [v for v in items if v.get("status") == status]
    return {"total": len(items), "items": items}


@app.get("/api/cloud/status")
def cloud_status():
    data = read_summary()
    return data.get("cloud", {})


@app.post("/api/vulnerabilities/classify")
async def classify_vulnerability(body: ClassifyBody):
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            r = await client.post(f"{AI_SERVICE_URL}/classify", json=body.model_dump())
            r.raise_for_status()
            return r.json()
    except httpx.HTTPError as e:
        raise HTTPException(503, f"AI service unavailable: {e}") from e


@app.get("/api/vulnerabilities/{vuln_id}/explain")
async def explain_vulnerability(vuln_id: str):
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            r = await client.get(f"{AI_SERVICE_URL}/explain/{vuln_id}")
            r.raise_for_status()
            return r.json()
    except httpx.HTTPError as e:
        raise HTTPException(503, f"AI explain failed: {e}") from e


@app.get("/api/remediation/summary")
def remediation_summary():
    """Before/after counts from AI-filtered Semgrep stats."""
    filtered = REPORTS_DIR / "semgrep-ai-filtered.json"
    semgrep = REPORTS_DIR / "semgrep-results.json"
    before = 0
    after = 0
    if semgrep.exists():
        data = json.loads(semgrep.read_text(encoding="utf-8"))
        before = len(data.get("results", []))
    if filtered.exists():
        data = json.loads(filtered.read_text(encoding="utf-8"))
        stats = data.get("stats", {})
        after = stats.get("total", before) - stats.get("filtered_fps", 0)
    return {
        "semgrep_before": before,
        "semgrep_after_ai": after,
        "reduction_pct": round((1 - after / before) * 100, 1) if before else 0,
    }


if STATIC_DIR.exists():
    app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")
