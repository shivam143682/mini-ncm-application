#!/usr/bin/env python3
"""
Cisco IOS Compliance Platform — End-to-End Demo
================================================
This script demonstrates the full workflow using the Python SDK:

1. Connects to the running API
2. Submits the sample Cisco IOS config
3. Displays the parsed configuration
4. Shows the compliance report
5. Lists all stored configs and reports

Prerequisites:
    pip install requests
    docker compose up --build  (API must be running on localhost:8000)

Usage:
    python examples/demo.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Add the project root to Python path so we can import the SDK
project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_root))

from sdk import CiscoComplianceClient


def separator(title: str) -> None:
    print(f"\n{'=' * 70}")
    print(f"  {title}")
    print(f"{'=' * 70}\n")


def main() -> None:
    # ── Step 0: Connect ──────────────────────────────────────────────────
    client = CiscoComplianceClient(base_url="http://localhost:8000")

    separator("1. Health Check")
    try:
        health = client.health_check()
        print(f"  Status : {health['status']}")
        print(f"  DB     : {health['db']}")
        print(f"  Version: {health['version']}")
    except Exception as exc:
        print(f"  ERROR: Cannot connect to API — {exc}")
        print("  Make sure the Docker stack is running: docker compose up --build")
        sys.exit(1)

    # ── Step 1: Load sample config ───────────────────────────────────────
    separator("2. Loading Sample Config")
    config_path = Path(__file__).parent / "sample_config.ios"
    config_text = config_path.read_text(encoding="utf-8")
    print(f"  File  : {config_path.name}")
    print(f"  Lines : {len(config_text.splitlines())}")

    # ── Step 2: Parse & evaluate ─────────────────────────────────────────
    separator("3. Submitting Config for Parsing & Compliance Check")
    result = client.parse_config(
        config_text=config_text,
        device_name="Core-Router-01",
    )

    config_info = result["config"]
    report_info = result["report"]
    parsed = result["parsed_data"]

    print(f"  Config ID : {config_info['id']}")
    print(f"  Device    : {config_info['device_name']}")
    print(f"  Parsed at : {config_info['created_at']}")

    # ── Step 3: Show parsed data ─────────────────────────────────────────
    separator("4. Parsed Configuration Summary")
    print(f"  Hostname       : {parsed.get('hostname', 'N/A')}")
    print(f"  Domain         : {parsed.get('domain_name', 'N/A')}")
    print(f"  SSH Version    : {parsed.get('ip_ssh_version', 'N/A')}")
    print(f"  AAA New Model  : {parsed.get('aaa_new_model', False)}")
    print(f"  Password Enc.  : {parsed.get('service_password_encryption', False)}")
    print(f"  Enable Secret  : {parsed.get('enable_secret', False)}")
    print(f"  Banner MOTD    : {'Yes' if parsed.get('banner_motd') else 'No'}")

    # Interfaces
    interfaces = parsed.get("interfaces", [])
    print(f"\n  Interfaces ({len(interfaces)}):")
    for intf in interfaces:
        status = "DOWN" if intf.get("shutdown") else "UP"
        ip = intf.get("ip_address") or "—"
        desc = intf.get("description") or "—"
        print(f"    {intf['name']:30s}  {ip:18s}  [{status}]  {desc}")

    # Routes
    routes = parsed.get("static_routes", [])
    print(f"\n  Static Routes ({len(routes)}):")
    for r in routes:
        print(f"    {r['network']:15s}  {r['mask']:15s}  -> {r['next_hop']}")

    # SNMP
    snmp = parsed.get("snmp_communities", [])
    print(f"\n  SNMP Communities ({len(snmp)}):")
    for s in snmp:
        print(f"    {s['community_string']:20s}  {s['access_type']}")

    # NTP
    ntp = parsed.get("ntp_servers", [])
    print(f"\n  NTP Servers ({len(ntp)}):")
    for n in ntp:
        pref = " (prefer)" if n.get("prefer") else ""
        print(f"    {n['address']}{pref}")

    # ── Step 4: Show compliance report ───────────────────────────────────
    separator("5. Compliance Report")
    print(f"  Report ID  : {report_info['id']}")
    print(f"  Score      : {report_info['score']} / 100")
    print(f"  Compliant  : {'YES' if report_info['is_compliant'] else 'NO'}")
    print(f"  Rules      : {report_info['passed_rules']} passed, "
          f"{report_info['failed_rules']} failed, "
          f"{report_info['total_rules']} total")

    print("\n  Rule Details:")
    print(f"  {'Rule ID':<10s} {'Severity':<10s} {'Status':<8s} {'Description'}")
    print(f"  {'-' * 10} {'-' * 10} {'-' * 8} {'-' * 40}")
    for rule in report_info["result_data"]["rules"]:
        icon = "[PASS]" if rule["status"] == "PASS" else "[FAIL]"
        print(
            f"  {rule['rule_id']:<10s} {rule['severity']:<10s} "
            f"{icon:<7s} {rule['description']}"
        )
        if rule["status"] != "PASS":
            print(f"  {'':>32s}  -> {rule['detail']}")

    # ── Step 5: List all configs ─────────────────────────────────────────
    separator("6. All Stored Configs")
    configs = client.list_configs()
    print(f"  Total: {len(configs)}")
    for c in configs:
        print(f"    [{c['id'][:8]}...]  {c.get('device_name', '-'):30s}  "
              f"lines={c['raw_lines']}  report={'yes' if c.get('has_report') else 'no'}")

    # ── Step 6: List all reports ──────────────────────────────────────────
    separator("7. All Compliance Reports")
    reports = client.list_reports()
    print(f"  Total: {len(reports)}")
    for r in reports:
        compliant = "COMPLIANT" if r.get("is_compliant") else "NON-COMPLIANT"
        print(f"    [{r['id'][:8]}...]  score={r['score']:.1f}  {compliant}")

    separator("Demo Complete")
    print("  The Cisco IOS Compliance Platform is working correctly!")
    print("  Open http://localhost:8000/docs for the Swagger UI.")
    print()


if __name__ == "__main__":
    main()
