#!/usr/bin/env python3
"""Interactive Terminal Dashboard & CLI for API Security Fuzzing Framework."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import webbrowser
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core import ResultManager, SecurityReporter, TargetManager
from modules.security.run_security_tests import (
    normalize_auth_header,
    parse_tokens_env,
    run_dynamic_target,
    run_target,
)

RESULTS = ResultManager(PROJECT_ROOT)
TARGETS = TargetManager(PROJECT_ROOT)
PYTHON = sys.executable
LAB_SCRIPT = PROJECT_ROOT / "lab" / "start_lab.py"


def _safe_input(prompt: str) -> str:
    try:
        return input(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        print("\nOperation cancelled.")
        return ""


def _clear_terminal() -> None:
    # Optional clear screen if supported, otherwise do not spam
    pass


def _render_menu_banner() -> None:
    print("\033[1;36m" + "╔" + "═" * 74 + "╗")
    print("║" + "   🛡️   API SECURITY FUZZING FRAMEWORK - CONTROL CENTER   🛡️   ".center(74) + "║")
    print("║" + "         Terminal Dashboard & Dynamic Security Ingestion Engine           ".center(74) + "║")
    print("╚" + "═" * 74 + "╝\033[0m")
    print(" \033[1mSelect an action from the menu below:\033[0m\n")
    print("  \033[1;32m[1]\033[0m 🎯 \033[1mRun Lab Targets\033[0m (crAPI, VAmPI, DVGA, or All)")
    print("  \033[1;32m[2]\033[0m 🌐 \033[1mScan Custom Target\033[0m (Dynamic URL, Schema, Auth Token)")
    print("  \033[1;32m[3]\033[0m 📊 \033[1mView Latest Dashboard\033[0m (Render directly in Terminal)")
    print("  \033[1;32m[4]\033[0m 🌍 \033[1mOpen HTML Web Report in Browser\033[0m (Interactive Dark Dashboard)")
    print("  \033[1;32m[5]\033[0m 📑 \033[1mGenerate Fresh HTML Report\033[0m (From findings history)")
    print("  \033[1;32m[6]\033[0m 🐳 \033[1mDocker Lab Management\033[0m (Start / Check Health / Stop)")
    print("  \033[1;31m[q]\033[0m 🚪 \033[1mExit\033[0m")
    print("\033[90m" + "─" * 76 + "\033[0m")


def _prompt_open_browser(report_path: Path | None) -> None:
    if report_path is None or not report_path.exists():
        return
    ans = _safe_input("\n🌐 Open interactive HTML report in browser now? [Y/n]: ").lower()
    if ans in {"", "y", "yes"}:
        try:
            webbrowser.open(report_path.as_uri())
            print(f"[+] Opened {report_path.name} in default browser.")
        except Exception as exc:
            print(f"[!] Could not open browser automatically: {exc}")


def _menu_run_lab() -> None:
    print("\n\033[1mConfigured Lab Targets:\033[0m")
    targets_list = sorted(TARGETS.targets.values(), key=lambda t: t.target_id)
    for idx, t in enumerate(targets_list, start=1):
        proto = t.settings.get("protocol", "rest").upper()
        print(f"  [{idx}] {t.name:<18} ({proto:<7} | {t.base_url})")
    print(f"  [{len(targets_list) + 1}] Run All Lab Targets")
    print("  [b] Back to Main Menu")

    choice = _safe_input("\nSelect target to run: ").lower()
    if choice in {"b", "back", ""}:
        return

    tokens = parse_tokens_env()
    selected_targets: list[str] = []

    if choice == str(len(targets_list) + 1):
        selected_targets = [t.target_id for t in targets_list]
    elif choice.isdigit() and 1 <= int(choice) <= len(targets_list):
        selected_targets = [targets_list[int(choice) - 1].target_id]
    elif choice in TARGETS.targets:
        selected_targets = [choice]
    else:
        print("[!] Invalid selection.")
        return

    for tid in selected_targets:
        try:
            run_target(tid, tokens=tokens, targets=TARGETS)
        except Exception as exc:
            print(f"[X] Target {tid} failed: {exc}", file=sys.stderr)

    # Render dashboard and HTML report
    reporter = SecurityReporter(RESULTS.results_dir)
    findings = reporter.load_latest_findings()
    if findings:
        reporter.render_terminal_dashboard(
            findings,
            target_info={"name": ", ".join(selected_targets), "url": "Configured Lab"},
        )
        report_path = reporter.generate_html_report(
            findings,
            target_info={"name": ", ".join(selected_targets), "url": "Configured Lab"},
        )
        print(f"\n[+] Interactive HTML Report saved to: {report_path}")
        _prompt_open_browser(report_path)


def _menu_scan_custom() -> None:
    print("\n\033[1;36m🌐 DYNAMIC TARGET SCAN CONFIGURATION\033[0m")
    print("Specify your target API settings below. No Docker required.\n")

    url = _safe_input("Target Base URL (e.g. http://localhost:8000 or https://api.example.com): ")
    if not url:
        print("[!] Base URL is required.")
        return

    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        print("[!] URL must start with http:// or https:// and include a host.")
        return

    protocol = _safe_input("Protocol [rest/graphql] (default rest): ").lower() or "rest"
    if protocol not in {"rest", "graphql"}:
        print("[!] Protocol must be 'rest' or 'graphql'.")
        return

    schema = ""
    endpoint = "/graphql"
    if protocol == "rest":
        schema = _safe_input("OpenAPI Schema URL or local file path (e.g. http://.../openapi.json or ./spec.yaml): ")
        if not schema:
            print("[!] REST target requires an OpenAPI schema source.")
            return
    else:
        endpoint = _safe_input("GraphQL endpoint [/graphql]: ") or "/graphql"

    auth_token = _safe_input("Auth Token (optional, Bearer token, JWT, or 'Header: Value'): ")
    payloads = _safe_input("Custom Payloads JSON file path (optional, press Enter to auto-generate): ")

    print("\n[i] Starting dynamic scan against:", url)
    exit_code = run_dynamic_target(
        url=url,
        schema=schema or None,
        auth_token=auth_token or None,
        protocol=protocol,
        endpoint=endpoint,
        payloads=payloads or None,
    )

    if exit_code == 0:
        latest = RESULTS.results_dir / "latest_report.html"
        _prompt_open_browser(latest)


def _menu_view_dashboard() -> None:
    reporter = SecurityReporter(RESULTS.results_dir)
    findings = reporter.load_latest_findings()
    if not findings:
        print("\n[!] No test findings found in results/. Run a test first!")
        return
    reporter.render_terminal_dashboard(findings)
    _safe_input("\nPress Enter to return to main menu...")


def _menu_open_report() -> None:
    latest = RESULTS.results_dir / "latest_report.html"
    if not latest.exists():
        reporter = SecurityReporter(RESULTS.results_dir)
        findings = reporter.load_findings()
        if not findings:
            print("\n[!] No results found to generate a report.")
            return
        latest = reporter.generate_html_report(findings)

    print(f"\n[+] Opening report: {latest}")
    try:
        webbrowser.open(latest.as_uri())
    except Exception as exc:
        print(f"[!] Failed to open browser: {exc}")
    _safe_input("\nPress Enter to return to main menu...")


def _menu_generate_html() -> None:
    reporter = SecurityReporter(RESULTS.results_dir)
    findings = reporter.load_findings()
    if not findings:
        print("\n[!] No findings found in results/ to generate report.")
        return
    report_path = reporter.generate_html_report(findings)
    print(f"\n[+] Generated standalone report: {report_path}")
    print(f"[+] Updated latest report link: {RESULTS.results_dir / 'latest_report.html'}")
    _prompt_open_browser(report_path)


def _menu_docker_lab() -> None:
    print("\n\033[1mDocker Lab Management:\033[0m")
    print("  [1] Start Lab Containers (crAPI, VAmPI, DVGA)")
    print("  [2] Check Container Health & HTTP Endpoints")
    print("  [3] Stop Lab Containers")
    print("  [b] Back")

    choice = _safe_input("\nSelect action: ").lower()
    if choice == "1":
        subprocess.run([PYTHON, str(LAB_SCRIPT), "start"], cwd=PROJECT_ROOT)
    elif choice == "2":
        subprocess.run([PYTHON, str(LAB_SCRIPT), "check"], cwd=PROJECT_ROOT)
    elif choice == "3":
        subprocess.run([PYTHON, str(LAB_SCRIPT), "stop"], cwd=PROJECT_ROOT)


def interactive_terminal_ui() -> int:
    """Run full interactive terminal website / console."""
    while True:
        _render_menu_banner()
        choice = _safe_input("Enter choice [1-6, q]: ").strip().lower()

        if choice in {"q", "quit", "exit"}:
            print("\nGoodbye! Happy security testing.")
            return 0
        elif choice == "1":
            _menu_run_lab()
        elif choice == "2":
            _menu_scan_custom()
        elif choice == "3":
            _menu_view_dashboard()
        elif choice == "4":
            _menu_open_report()
        elif choice == "5":
            _menu_generate_html()
        elif choice == "6":
            _menu_docker_lab()
        else:
            print("\n[!] Invalid choice. Please enter 1-6 or q.")
        print()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="API Security Testing CLI - Run interactively or specify target directly.",
    )
    parser.add_argument("--url", default=None, help="Target base URL (e.g. https://api.example.com)")
    parser.add_argument("--schema", default=None, help="OpenAPI schema path or URL (required for REST)")
    parser.add_argument("--auth-token", "--token", dest="auth_token", default=None, help="Bearer token, JWT, or 'Header: Value'")
    parser.add_argument("--protocol", choices=["rest", "graphql"], default="rest", help="Protocol (default: rest)")
    parser.add_argument("--endpoint", default="/graphql", help="GraphQL endpoint (default: /graphql)")
    parser.add_argument("--payloads", default=None, help="Path to custom payload corpus JSON")
    parser.add_argument("--target-id", default=None, help="Identifier for dynamic target")
    parser.add_argument("--name", default=None, help="Display name for dynamic target")
    parser.add_argument("--report", action="store_true", help="Generate and open the latest HTML report in browser")
    parser.add_argument("--dashboard", action="store_true", help="Print the latest security dashboard to the terminal")
    parser.add_argument("--interactive", "-i", action="store_true", help="Force interactive terminal dashboard")

    passed_args = sys.argv[1:] if argv is None else argv
    if not passed_args:
        args = parser.parse_args([])
    else:
        args = parser.parse_args(passed_args)

    if args.dashboard:
        reporter = SecurityReporter(RESULTS.results_dir)
        findings = reporter.load_latest_findings()
        reporter.render_terminal_dashboard(findings)
        return 0

    if args.report:
        _menu_open_report()
        return 0

    if args.url and not args.interactive:
        return run_dynamic_target(
            url=args.url,
            schema=args.schema,
            auth_token=args.auth_token,
            protocol=args.protocol,
            endpoint=args.endpoint,
            payloads=args.payloads,
            target_id=args.target_id,
            name=args.name,
        )

    # Interactive terminal website mode
    return interactive_terminal_ui()


if __name__ == "__main__":
    raise SystemExit(main())
