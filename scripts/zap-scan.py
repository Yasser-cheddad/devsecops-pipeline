#!/usr/bin/env python3
"""
OWASP ZAP Automation Script
PFE DevSecOps – EST Cybersécurité
Usage: python3 zap-scan.py --target http://app:3000 --zap-host zap --zap-port 8080
"""

import argparse
import json
import sys
import time
import requests
from zapv2 import ZAPv2


def wait_for_zap(zap_url: str, timeout: int = 120):
    print(f"⏳ Waiting for ZAP at {zap_url}...")
    for i in range(timeout):
        try:
            r = requests.get(f"{zap_url}/JSON/core/view/version/", timeout=3)
            if r.status_code == 200:
                version = r.json().get("version", "unknown")
                print(f"✅ ZAP ready (version {version})")
                return True
        except Exception:
            pass
        time.sleep(1)
    print("❌ ZAP did not become ready in time")
    return False


def wait_for_target(target_url: str, timeout: int = 120):
    print(f"⏳ Waiting for target at {target_url}...")
    for i in range(timeout):
        try:
            r = requests.get(target_url, timeout=5)
            if r.status_code < 500:
                print(f"✅ Target ready (HTTP {r.status_code})")
                return True
        except Exception:
            pass
        time.sleep(1)
    print("❌ Target did not become ready in time")
    return False


def load_rules(rules_file: str) -> dict:
    """Load ZAP alert filter rules from config file."""
    rules = {}
    try:
        with open(rules_file) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    parts = line.split("=")
                    if len(parts) == 2:
                        rules[parts[0].strip()] = parts[1].strip()
        print(f"📋 Loaded {len(rules)} custom rules from {rules_file}")
    except FileNotFoundError:
        print(f"⚠️  Rules file {rules_file} not found, using defaults")
    return rules


def run_spider(zap: ZAPv2, target: str):
    print(f"\n🕷️  Starting Spider on {target}...")
    scan_id = zap.spider.scan(target)
    while int(zap.spider.status(scan_id)) < 100:
        progress = zap.spider.status(scan_id)
        print(f"   Spider progress: {progress}%", end="\r")
        time.sleep(2)
    print(f"\n✅ Spider completed. URLs found: {len(zap.spider.results(scan_id))}")


def run_ajax_spider(zap: ZAPv2, target: str):
    print(f"\n🕷️  Starting AJAX Spider on {target}...")
    zap.ajaxSpider.scan(target)
    timeout = 60
    start = time.time()
    while zap.ajaxSpider.status == "running":
        if time.time() - start > timeout:
            zap.ajaxSpider.stop()
            break
        time.sleep(2)
    print("✅ AJAX Spider completed")


def run_active_scan(zap: ZAPv2, target: str):
    print(f"\n⚔️  Starting Active Scan on {target}...")
    scan_id = zap.ascan.scan(target)
    while int(zap.ascan.status(scan_id)) < 100:
        progress = zap.ascan.status(scan_id)
        print(f"   Active scan progress: {progress}%", end="\r")
        time.sleep(5)
    print(f"\n✅ Active scan completed")


def get_alerts(zap: ZAPv2, target: str) -> list:
    alerts = zap.core.alerts(baseurl=target)
    return alerts


def filter_false_positives(alerts: list, rules: dict) -> list:
    """Remove alerts that are marked as false positives in rules."""
    fp_ids = {k for k, v in rules.items() if v.lower() == "false_positive"}
    filtered = [a for a in alerts if str(a.get("pluginId", "")) not in fp_ids]
    removed = len(alerts) - len(filtered)
    if removed:
        print(f"🔧 Filtered {removed} false positive alert(s) via rules file")
    return filtered


def build_report(alerts: list, target: str) -> dict:
    risk_map = {"0": "Informational", "1": "Low", "2": "Medium", "3": "High", "4": "Critical"}
    summary = {"high": 0, "medium": 0, "low": 0, "informational": 0}

    for a in alerts:
        risk = risk_map.get(str(a.get("riskcode", "0")), "informational").lower()
        summary[risk] = summary.get(risk, 0) + 1

    return {
        "target": target,
        "summary": summary,
        "total_alerts": len(alerts),
        "site": [{"alerts": alerts}],
    }


def save_report(report: dict, output_path: str):
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n📄 Report saved to {output_path}")


def generate_html_report(zap: ZAPv2, output_path: str):
    html = zap.core.htmlreport()
    html_path = output_path.replace(".json", ".html")
    with open(html_path, "w") as f:
        f.write(html)
    print(f"📄 HTML report saved to {html_path}")


def evaluate_gate(summary: dict, fail_on_high: bool = True) -> bool:
    """Returns True if pipeline should FAIL."""
    print("\n📊 Security Gate Evaluation:")
    print(f"   High:          {summary['high']}")
    print(f"   Medium:        {summary['medium']}")
    print(f"   Low:           {summary['low']}")
    print(f"   Informational: {summary['informational']}")

    if fail_on_high and summary["high"] >= 1:
        print("❌ SECURITY GATE FAILED: ≥1 High severity alert found")
        return True
    print("✅ DAST security gate passed")
    return False


def main():
    parser = argparse.ArgumentParser(description="OWASP ZAP DAST Scanner")
    parser.add_argument("--target", required=True, help="Target URL to scan")
    parser.add_argument("--zap-host", default="localhost", help="ZAP host")
    parser.add_argument("--zap-port", default="8080", help="ZAP port")
    parser.add_argument("--output", default="reports/zap-results.json", help="Output JSON path")
    parser.add_argument("--rules", default="security-tools/zap/zap-rules.conf", help="Rules file")
    parser.add_argument("--no-active-scan", action="store_true", help="Skip active scan")
    args = parser.parse_args()

    zap_url = f"http://{args.zap_host}:{args.zap_port}"

    if not wait_for_zap(zap_url):
        sys.exit(1)
    if not wait_for_target(args.target):
        sys.exit(1)

    zap = ZAPv2(proxies={"http": zap_url, "https": zap_url})
    rules = load_rules(args.rules)

    # Passive scan via spider
    run_spider(zap, args.target)
    run_ajax_spider(zap, args.target)

    # Wait for passive scan to complete
    print("\n⏳ Waiting for passive scan...")
    while int(zap.pscan.records_to_scan) > 0:
        print(f"   Passive scan queue: {zap.pscan.records_to_scan}", end="\r")
        time.sleep(2)
    print("\n✅ Passive scan complete")

    # Active scan
    if not args.no_active_scan:
        run_active_scan(zap, args.target)

    # Collect & filter alerts
    raw_alerts = get_alerts(zap, args.target)
    alerts = filter_false_positives(raw_alerts, rules)
    report = build_report(alerts, args.target)

    # Save reports
    save_report(report, args.output)
    generate_html_report(zap, args.output)

    # Evaluate gate
    gate_failed = evaluate_gate(report["summary"])
    sys.exit(1 if gate_failed else 0)


if __name__ == "__main__":
    main()
