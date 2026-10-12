#!/usr/bin/env python3
"""Merge security scan artifacts into one dashboard JSON file."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

REPORTS = Path(os.getenv("REPORTS_DIR", "reports"))
OUT = REPORTS / "dashboard-summary.json"

GATES = [
    ("secret-detection", "trufflehog-report.json", "verified secrets"),
    ("semgrep-sast", "semgrep-results.json", "critical findings"),
    ("snyk-sca", "snyk-results.json", "dependency vulns"),
    ("trivy-container-scan", "trivy-results.json", "image CVEs"),
    ("owasp-zap-dast", "zap-results.json", "DAST alerts"),
]


def load_json(path: Path):
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def semgrep_vulns(data: dict) -> list[dict]:
    items = []
    filtered = load_json(REPORTS / "semgrep-ai-filtered.json")
    source = filtered.get("results", []) if filtered else data.get("results", [])
    for i, r in enumerate(source):
        extra = r.get("extra", {})
        ai = r.get("ai", {})
        items.append(
            {
                "id": r.get("check_id", f"sg-{i}") + f"-{i}",
                "tool": "semgrep",
                "severity": extra.get("severity", "INFO"),
                "title": extra.get("message", r.get("check_id", "")),
                "file": r.get("path"),
                "line": r.get("start", {}).get("line"),
                "status": "filtered" if ai.get("filtered") else "open",
                "ai_score": ai.get("score"),
                "ai_label": ai.get("label"),
            }
        )
    return items


def snyk_vulns(data: dict) -> list[dict]:
    items = []
    for i, v in enumerate(data.get("vulnerabilities", [])):
        items.append(
            {
                "id": f"snyk-{i}",
                "tool": "snyk",
                "severity": v.get("severity", "unknown").upper(),
                "title": v.get("title", v.get("name", "dependency issue")),
                "file": v.get("from", [""])[0] if isinstance(v.get("from"), list) else "",
                "cve": (v.get("identifiers", {}) or {}).get("CVE", [None])[0],
                "fix_version": v.get("fixedIn"),
                "status": "open",
            }
        )
    return items


def trivy_vulns(data: dict) -> list[dict]:
    items = []
    for res in data.get("Results", []):
        for i, v in enumerate(res.get("Vulnerabilities") or []):
            items.append(
                {
                    "id": f"trivy-{v.get('VulnerabilityID', i)}",
                    "tool": "trivy",
                    "severity": v.get("Severity", "UNKNOWN"),
                    "title": v.get("Title", v.get("VulnerabilityID", "")),
                    "cve": v.get("VulnerabilityID"),
                    "status": "open",
                }
            )
    return items


def zap_vulns(data: dict) -> list[dict]:
    alerts = data.get("alerts") or data.get("site", [{}])[0].get("alerts", [])
    items = []
    for i, a in enumerate(alerts):
        if isinstance(a, dict) and "alert" in a:
            a = a["alert"]
        items.append(
            {
                "id": f"zap-{i}",
                "tool": "zap",
                "severity": (a.get("risk") or a.get("riskdesc", "Info")).split()[0].upper(),
                "title": a.get("name", a.get("alert", "ZAP alert")),
                "status": "open",
            }
        )
    return items


def gate_status(name: str, filename: str) -> dict:
    path = REPORTS / filename
    present = path.exists()
    status = "passed" if present else "skipped"
    detail = ""
    if present and name == "semgrep-sast":
        data = load_json(path) or {}
        crit = [
            r
            for r in data.get("results", [])
            if r.get("extra", {}).get("severity") in ("ERROR", "CRITICAL")
        ]
        status = "failed" if crit else "passed"
        detail = f"{len(crit)} critical"
    return {"stage": name, "status": status, "artifact": filename if present else None, "detail": detail}


def main() -> int:
    REPORTS.mkdir(parents=True, exist_ok=True)
    vulns: list[dict] = []

    semgrep = load_json(REPORTS / "semgrep-results.json")
    if semgrep:
        vulns.extend(semgrep_vulns(semgrep))

    snyk = load_json(REPORTS / "snyk-results.json")
    if snyk:
        vulns.extend(snyk_vulns(snyk))

    trivy = load_json(REPORTS / "trivy-results.json")
    if trivy:
        vulns.extend(trivy_vulns(trivy))

    zap = load_json(REPORTS / "zap-results.json")
    if zap:
        vulns.extend(zap_vulns(zap))

    ai_stats = load_json(REPORTS / "semgrep-ai-filtered.json")
    ai_block = (ai_stats or {}).get("stats", {})

    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "pipeline": {
            "id": os.getenv("CI_PIPELINE_ID"),
            "ref": os.getenv("CI_COMMIT_REF_NAME"),
            "sha": os.getenv("CI_COMMIT_SHORT_SHA"),
            "url": os.getenv("CI_PIPELINE_URL"),
        },
        "gates": [gate_status(n, f, _) for n, f, _ in GATES],
        "ai": ai_block,
        "cloud": {
            "provider": "aws",
            "environment": os.getenv("CI_ENVIRONMENT_NAME", "staging"),
            "app_url": os.getenv("APP_URL") or os.getenv("CI_ENVIRONMENT_URL"),
            "ecs_cluster": os.getenv("ECS_CLUSTER", "pfe-devsecops-cluster"),
            "ecs_service": os.getenv("ECS_SERVICE", "pfe-devsecops-service"),
        },
        "vulnerabilities": vulns,
        "counts": {
            "total": len(vulns),
            "by_tool": {},
            "by_severity": {},
        },
    }

    for v in vulns:
        summary["counts"]["by_tool"][v["tool"]] = summary["counts"]["by_tool"].get(v["tool"], 0) + 1
        sev = str(v.get("severity", "unknown")).upper()
        summary["counts"]["by_severity"][sev] = summary["counts"]["by_severity"].get(sev, 0) + 1

    OUT.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"Wrote {OUT} ({len(vulns)} vulnerabilities)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
