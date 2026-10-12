#!/usr/bin/env python3
"""Run AI classification on Semgrep findings and write filtered report."""

from __future__ import annotations

import json
import os
import sys
import uuid
from pathlib import Path

import urllib.error
import urllib.request

REPORTS = Path(os.getenv("REPORTS_DIR", "reports"))
SEMGREP_IN = REPORTS / "semgrep-results.json"
SEMGREP_OUT = REPORTS / "semgrep-ai-filtered.json"
AI_URL = os.getenv("AI_SERVICE_URL", "http://localhost:8001").rstrip("/")

SEVERITY_MAP = {"CRITICAL": 4, "ERROR": 4, "HIGH": 3, "WARNING": 2, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def rule_score(severity: str, title: str, path: str) -> tuple[float, str]:
    sev = SEVERITY_MAP.get(severity.upper(), 0)
    score = sev / 4.0
    title_l = title.lower()
    if any(k in title_l for k in ("sql", "injection", "xss", "command")):
        score = min(score + 0.15, 1.0)
    if any(k in (path or "").lower() for k in ("test", "spec", "mock", "__test__")):
        score = max(score - 0.25, 0.0)
    label = "true_positive" if score > 0.5 else "false_positive"
    return round(score, 3), label


def classify_http(payload: dict) -> dict | None:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        f"{AI_URL}/classify",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        return None


def semgrep_to_vuln(result: dict, idx: int) -> dict:
    extra = result.get("extra", {})
    sev = extra.get("severity", "INFO")
    return {
        "id": result.get("check_id", f"semgrep-{idx}") + f"-{idx}",
        "tool": "semgrep",
        "severity": sev,
        "title": extra.get("message", result.get("check_id", "finding")),
        "description": extra.get("message", ""),
        "file": result.get("path", ""),
        "line": result.get("start", {}).get("line"),
    }


def main() -> int:
    REPORTS.mkdir(parents=True, exist_ok=True)
    if not SEMGREP_IN.exists():
        print(f"No Semgrep report at {SEMGREP_IN}")
        SEMGREP_OUT.write_text(json.dumps({"results": [], "stats": {"total": 0}}))
        return 0

    data = json.loads(SEMGREP_IN.read_text(encoding="utf-8"))
    findings = data.get("results", [])
    enriched = []
    filtered_count = 0

    for i, r in enumerate(findings):
        vuln = semgrep_to_vuln(r, i)
        ai = classify_http(vuln)
        if ai is None:
            score, label = rule_score(vuln["severity"], vuln["title"], vuln.get("file", ""))
            ai = {
                "id": vuln["id"],
                "label": label,
                "score": score,
                "filtered": label == "false_positive",
                "risk_level": "high" if score > 0.6 else "medium",
                "source": "rules",
            }
        else:
            ai["source"] = "model"
        if ai.get("filtered"):
            filtered_count += 1
        enriched.append({**r, "ai": ai})

    total = len(findings) or 1
    fp_pct = round(filtered_count / total * 100, 1)
    out = {
        "pipeline_id": os.getenv("CI_PIPELINE_ID", "local"),
        "commit": os.getenv("CI_COMMIT_SHORT_SHA", "local"),
        "stats": {
            "total": len(findings),
            "filtered_fps": filtered_count,
            "fp_reduction_pct": fp_pct,
        },
        "results": enriched,
    }
    SEMGREP_OUT.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(f"AI filter: {filtered_count}/{len(findings)} marked false positive ({fp_pct}%)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
