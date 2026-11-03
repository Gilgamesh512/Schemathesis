#!/usr/bin/env python3
"""Interactive Terminal Dashboard & Universal API Security Scanner CLI."""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import webbrowser
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from core import (
    ResultManager,
    SecurityReporter,
    TargetConfig,
    TargetManager,
    discover_api,
)
from modules.security.run_security_tests import (
    normalize_auth_header,
    parse_tokens_env,
    run_dynamic_target,
    run_target,
    run_workflow,
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


def _render_menu_banner() -> None:
    print("\033[1;36m")
    print("  ███████╗ ██████╗ ██╗  ██╗███████╗███╗   ███╗ █████╗ ████████╗██╗  ██╗███████╗███████╗██╗███████╗")
    print("  ██╔════╝██╔════╝ ██║  ██║██╔════╝████╗ ████║██╔══██╗╚══██╔══╝██║  ██║██╔════╝██╔════╝██║██╔════╝")
    print("  ███████╗██║      ███████║█████╗  ██╔████╔██║███████║   ██║   ███████║█████╗  ███████╗██║███████╗")
    print("  ╚════██║██║      ██╔══██║██╔══╝  ██║╚██╔╝██║██╔══██║   ██║   ██╔══██║██╔══╝  ╚════██║██║╚════██║")
    print("  ███████║╚██████╗ ██║  ██║███████╗██║ ╚═╝ ██║██║  ██║   ██║   ██║  ██║███████╗███████║██║███████║")
    print("  ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝╚══════╝\033[0m")
    print("\033[1;33m" + "                     🛡️  HỆ THỐNG KIỂM THỬ BẢO MẬT API - SCHEMATHESIS PRO  🛡️".center(98) + "\033[0m")
    print("\033[90m" + "                   Universal Vulnerability Scanner • OWASP API Top 10 • Auto-Discovery".center(98) + "\033[0m\n")
    print(" \033[1mSelect an action from the menu below:\033[0m\n")
    print("  \033[1;32m[1]\033[0m 🚀 \033[1mQuick Scan Any API\033[0m (Paste URL -> Auto-Discover Schema -> Fuzz -> Report)")
    print("  \033[1;32m[2]\033[0m 🎯 \033[1mRun Saved Target\033[0m (Select from your saved target profiles)")
    print("  \033[1;32m[3]\033[0m 📂 \033[1mManage Saved Targets\033[0m (Add, Inspect, or Delete custom API targets)")
    print("  \033[1;32m[4]\033[0m 📊 \033[1mView Latest Dashboard\033[0m (Render OWASP Top 10 KPIs directly in Terminal)")
    print("  \033[1;32m[5]\033[0m 🌍 \033[1mOpen HTML Web Report in Browser\033[0m (Interactive Dark Dashboard)")
    print("  \033[1;32m[6]\033[0m 📑 \033[1mExport Fresh Reports\033[0m (Standalone HTML & OASIS SARIF v2.1 for CI/CD)")
    print("  \033[1;32m[7]\033[0m 🔄 \033[1mRun Stateful Workflow YAML\033[0m (Multi-step business logic & BOLA testing)")
    print("  \033[1;33m[8]\033[0m 🧪 \033[1mDemo Labs & Docker\033[0m (crAPI, VAmPI, DVGA container operations)")
    print("  \033[1;31m[q]\033[0m 🚪 \033[1mExit\033[0m")
    print("\033[90m" + "─" * 97 + "\033[0m")


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


def _menu_quick_scan() -> None:
    print("\n\033[1;36m🚀 QUICK SCAN - TARGET-AGNOSTIC SECURITY AUDIT\033[0m")
    print("Just paste any API base URL. The engine will auto-probe for OpenAPI/Swagger/GraphQL.\n")

    url = _safe_input("Target Base URL (e.g. https://api.example.com or http://localhost:8000): ")
    if not url:
        print("[!] Base URL is required.")
        return

    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        print("[!] URL must start with http:// or https:// and include a host.")
        return

    # Check for authentication
    auth_token = _safe_input("Auth Token (optional, Bearer token, JWT, or 'Header: Value'): ")
    proxy = _safe_input("Upstream Proxy URL (optional, e.g. http://127.0.0.1:8080 for Burp): ") or None
    insecure = False
    if proxy or parsed.scheme == "https":
        insecure_ans = _safe_input("Disable SSL certificate verification? [y/N]: ").lower()
        insecure = insecure_ans in {"y", "yes"}

    # Probing schema via Auto-Discovery
    print("\n[🔍] Probing API target for specifications...")
    headers = {"Authorization": normalize_auth_header(auth_token)} if auth_token else {}
    disc = discover_api(url, proxy=proxy, insecure=insecure, headers=headers)

    schema: str | None = None
    protocol = "rest"
    endpoint = "/graphql"

    if disc.is_discovered:
        if disc.protocol == "graphql":
            protocol = "graphql"
            endpoint = disc.endpoint or "/graphql"
            print(f"\033[1;32m[✓] Discovered GraphQL API!\033[0m Endpoint: {endpoint}")
        elif disc.schema_url:
            schema = disc.schema_url
            print(f"\033[1;32m[✓] Discovered OpenAPI/Swagger Specification!\033[0m Source: {schema}")
            if disc.title:
                print(f"    API Title: \033[1m{disc.title}\033[0m (version: {disc.version or 'unknown'})")
    else:
        print("\033[1;33m[!] Could not automatically detect OpenAPI or GraphQL schema.\033[0m")
        alt = _safe_input("Path/URL to Schema file, Postman collection, or HAR log (or press Enter to cancel): ")
        if not alt:
            print("[!] Cancelled.")
            return
        schema = alt

    # Option to save target
    save_ans = _safe_input("\nSave this target to your saved profiles for future one-click scans? [Y/n]: ").lower()
    save_profile = save_ans in {"", "y", "yes"}

    custom_name = None
    if save_profile:
        def_name = disc.title or f"API_{parsed.netloc.replace(':', '_')}"
        custom_name = _safe_input(f"Target Display Name [{def_name}]: ") or def_name

    print("\n[i] Starting automated security fuzzing pipeline against:", url)
    exit_code = run_dynamic_target(
        url=url,
        schema=schema,
        auth_token=auth_token or None,
        protocol=protocol,
        endpoint=endpoint,
        proxy=proxy,
        insecure=insecure,
        name=custom_name,
        save_profile=save_profile,
        targets=TARGETS,
    )

    if exit_code == 0:
        latest = RESULTS.results_dir / "latest_report.html"
        _prompt_open_browser(latest)


def _menu_run_saved_target() -> None:
    TARGETS.refresh()
    custom_profiles = TARGETS.list_custom_profiles()
    lab_profiles = TARGETS.list_lab_profiles()

    print("\n\033[1;36m🎯 SELECT SAVED TARGET TO RUN\033[0m\n")
    if not custom_profiles and not lab_profiles:
        print("  [!] No targets found. Use [1] Quick Scan or [3] Manage Saved Targets to add one.")
        _safe_input("\nPress Enter to continue...")
        return

    all_profiles = custom_profiles + lab_profiles
    for idx, t in enumerate(all_profiles, start=1):
        proto = t.settings.get("protocol", "rest").upper()
        tag = "\033[1;32m[Custom]\033[0m" if t in custom_profiles else "\033[1;33m[Lab]\033[0m"
        auth_status = "Auth: Configured" if t.auth else "Auth: None"
        print(f"  [{idx}] {tag:<17} \033[1m{t.name:<22}\033[0m ({proto:<7} | {auth_status:<16} | {t.base_url})")

    print(f"  [a] Run All Saved Custom Targets ({len(custom_profiles)} targets)")
    print("  [b] Back to Main Menu")

    choice = _safe_input("\nSelect target number to run: ").lower()
    if choice in {"b", "back", ""}:
        return

    selected: list[TargetConfig] = []
    if choice == "a":
        selected = custom_profiles if custom_profiles else all_profiles
    elif choice.isdigit() and 1 <= int(choice) <= len(all_profiles):
        selected = [all_profiles[int(choice) - 1]]
    else:
        print("[!] Invalid selection.")
        return

    tokens = parse_tokens_env()
    for tgt in selected:
        try:
            run_target(tgt.target_id, tokens=tokens, targets=TARGETS)
        except Exception as exc:
            print(f"[X] Target {tgt.name} failed: {exc}", file=sys.stderr)

    reporter = SecurityReporter(RESULTS.results_dir)
    findings = reporter.load_latest_findings()
    if findings:
        names = ", ".join(t.name for t in selected)
        reporter.render_terminal_dashboard(findings, target_info={"name": names, "url": "Saved Target Suite"})
        report_path = reporter.generate_html_report(findings, target_info={"name": names, "url": "Saved Target Suite"})
        print(f"\n[+] Interactive HTML Report saved to: {report_path}")
        _prompt_open_browser(report_path)


def _menu_manage_targets() -> None:
    while True:
        TARGETS.refresh()
        custom = TARGETS.list_custom_profiles()
        print("\n\033[1;36m📂 SAVED TARGETS MANAGER\033[0m")
        print(f"Total Custom Profiles: {len(custom)}\n")

        if custom:
            for idx, t in enumerate(custom, start=1):
                proto = t.settings.get("protocol", "rest").upper()
                print(f"  [{idx}] \033[1m{t.name}\033[0m (ID: {t.target_id} | {proto} | {t.base_url})")
                if t.schema_source:
                    print(f"      Schema: {t.schema_source}")
        else:
            print("  (No custom target profiles saved yet. Add one below!)")

        print("\nActions:")
        print("  [a] ➕ Add New Target Profile")
        print("  [d] 🗑️  Delete a Target Profile")
        print("  [b] ⬅️  Back to Main Menu")

        act = _safe_input("\nSelect action [a/d/b]: ").lower()
        if act in {"b", "back", ""}:
            break
        elif act == "a":
            _sub_add_target()
        elif act == "d":
            _sub_delete_target(custom)


def _sub_add_target() -> None:
    print("\n\033[1mAdd New Target Profile:\033[0m")
    url = _safe_input("Target Base URL: ")
    if not url:
        return
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        print("[!] Invalid URL.")
        return

    # Auto-discovery
    print("[🔍] Probing API target for specifications...")
    disc = discover_api(url)
    default_schema = disc.schema_url or ""
    default_proto = disc.protocol
    default_name = disc.title or f"API {parsed.netloc}"

    name = _safe_input(f"Target Name [{default_name}]: ") or default_name
    protocol = _safe_input(f"Protocol [rest/graphql] [{default_proto}]: ").lower() or default_proto

    schema_source = None
    if protocol == "rest":
        prompt_str = f"OpenAPI/Postman/HAR Schema URL or File Path [{default_schema}]: " if default_schema else "Schema URL or File Path: "
        schema_source = _safe_input(prompt_str) or default_schema
        if not schema_source:
            print("[!] REST targets require a schema source.")
            return

    token = _safe_input("Auth Token (Bearer token, JWT, or 'Header: Value', optional): ")
    proxy = _safe_input("Upstream Proxy URL (optional): ") or None

    host_clean = re.sub(r"[^a-z0-9_-]", "_", parsed.netloc.split(":")[0].lower()).strip("_")
    tid_cand = f"target_{host_clean}"
    target_id = _safe_input(f"Target Identifier [{tid_cand}]: ").lower() or tid_cand

    auth: dict[str, Any] = {}
    if token:
        auth["header"] = normalize_auth_header(token)

    settings: dict[str, Any] = {"protocol": protocol}
    if proxy:
        settings["proxy"] = proxy
    if schema_source and schema_source.startswith(("http://", "https://")):
        settings["allow_remote_schema"] = True

    try:
        TARGETS.add_target(
            target_id=target_id,
            name=name,
            base_url=url,
            schema_source=schema_source,
            auth=auth,
            settings=settings,
        )
        saved_file = TARGETS.save_profile(target_id, overwrite=True)
        print(f"\n\033[1;32m[+] Successfully created and saved profile: {saved_file}\033[0m")
    except Exception as exc:
        print(f"[X] Failed to save profile: {exc}")


def _sub_delete_target(custom: list[TargetConfig]) -> None:
    if not custom:
        print("[!] No custom profiles available to delete.")
        return
    idx_str = _safe_input("Enter target number or ID to delete: ")
    tid_to_delete = None
    if idx_str.isdigit() and 1 <= int(idx_str) <= len(custom):
        tid_to_delete = custom[int(idx_str) - 1].target_id
    elif any(t.target_id == idx_str.strip().lower() for t in custom):
        tid_to_delete = idx_str.strip().lower()

    if not tid_to_delete:
        print("[!] Invalid target.")
        return

    confirm = _safe_input(f"Are you sure you want to delete profile '{tid_to_delete}'? [y/N]: ").lower()
    if confirm in {"y", "yes"}:
        if TARGETS.delete_profile(tid_to_delete):
            print(f"[+] Deleted profile '{tid_to_delete}'.")
        else:
            print(f"[!] Could not delete profile '{tid_to_delete}'.")


def _menu_view_dashboard() -> None:
    reporter = SecurityReporter(RESULTS.results_dir)
    findings = reporter.load_latest_findings()
    if not findings:
        print("\n[!] No test findings found in results/. Run a scan first!")
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
    sarif_path = RESULTS.results_dir / "vulnerabilities.sarif"
    print(f"\n[+] Generated standalone HTML report: {report_path}")
    print(f"[+] Updated latest report link:       {RESULTS.results_dir / 'latest_report.html'}")
    if sarif_path.exists():
        print(f"[+] Exported OASIS SARIF report:     {sarif_path}")
    _prompt_open_browser(report_path)


def _menu_demo_labs() -> None:
    print("\n\033[1;33m🧪 DEMO LABS & DOCKER MANAGEMENT\033[0m")
    print("These are pre-configured vulnerable testing applications (crAPI, VAmPI, DVGA).\n")
    print("  [1] 🎯 Run Lab Fuzzing (crAPI, VAmPI, DVGA)")
    print("  [2] 🐳 Start Lab Docker Containers")
    print("  [3] 🔍 Check Lab Containers Health")
    print("  [4] 🛑 Stop Lab Containers")
    print("  [b] ⬅️  Back to Main Menu")

    choice = _safe_input("\nSelect action: ").lower()
    if choice == "1":
        tokens = parse_tokens_env()
        lab_tids = [t.target_id for t in TARGETS.list_lab_profiles()]
        for tid in lab_tids:
            try:
                run_target(tid, tokens=tokens, targets=TARGETS)
            except Exception as exc:
                print(f"[X] Lab target {tid} failed: {exc}", file=sys.stderr)
    elif choice == "2":
        subprocess.run([PYTHON, str(LAB_SCRIPT), "start"], cwd=PROJECT_ROOT)
    elif choice == "3":
        subprocess.run([PYTHON, str(LAB_SCRIPT), "check"], cwd=PROJECT_ROOT)
    elif choice == "4":
        subprocess.run([PYTHON, str(LAB_SCRIPT), "stop"], cwd=PROJECT_ROOT)


def _menu_run_workflow() -> None:
    print("\n\033[1;36m🔄 STATEFUL WORKFLOW EXECUTION\033[0m")
    print("Execute multi-step API workflows with dynamic variable extraction and BOLA validation.\n")

    default_wf = "targets/workflows/sample_workflow.yaml"
    wf_path = _safe_input(f"Path to workflow YAML file [{default_wf}]: ") or default_wf
    base_url = _safe_input("Base URL override (optional, e.g. http://localhost:5002): ") or None
    proxy = _safe_input("Upstream Proxy URL (optional, e.g. http://127.0.0.1:8080): ") or None
    insecure_ans = _safe_input("Disable SSL verification? [y/N]: ").lower()
    insecure = insecure_ans in {"y", "yes"}

    try:
        run_workflow(
            wf_path,
            base_url=base_url,
            proxy=proxy,
            insecure=insecure,
        )
    except Exception as exc:
        print(f"\n[X] Workflow failed: {exc}", file=sys.stderr)

    _safe_input("\nPress Enter to return to main menu...")


def interactive_terminal_ui() -> int:
    """Run full interactive terminal website / console."""
    while True:
        _render_menu_banner()
        choice = _safe_input("Enter choice [1-8, q]: ").strip().lower()

        if choice in {"q", "quit", "exit"}:
            print("\nGoodbye! Happy security testing.")
            return 0
        elif choice == "1":
            _menu_quick_scan()
        elif choice == "2":
            _menu_run_saved_target()
        elif choice == "3":
            _menu_manage_targets()
        elif choice == "4":
            _menu_view_dashboard()
        elif choice == "5":
            _menu_open_report()
        elif choice == "6":
            _menu_generate_html()
        elif choice == "7":
            _menu_run_workflow()
        elif choice == "8":
            _menu_demo_labs()
        else:
            print("\n[!] Invalid choice. Please enter 1-8 or q.")
        print()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Universal API Security Testing CLI - Run interactively or specify target directly.",
    )
    parser.add_argument("--url", default=None, help="Target base URL (e.g. https://api.example.com)")
    parser.add_argument("--schema", default=None, help="OpenAPI schema path or URL (auto-discovered if omitted)")
    parser.add_argument("--postman", default=None, help="Postman collection JSON file path")
    parser.add_argument("--har", default=None, help="HTTP Archive (.har) log file path")
    parser.add_argument("--workflow", default=None, help="Stateful workflow YAML file path")
    parser.add_argument("--auth-token", "--token", dest="auth_token", default=None, help="Bearer token, JWT, or 'Header: Value'")
    parser.add_argument("--protocol", choices=["rest", "graphql"], default="rest", help="Protocol (default: rest)")
    parser.add_argument("--endpoint", default="/graphql", help="GraphQL endpoint (default: /graphql)")
    parser.add_argument("--payloads", default=None, help="Path to custom payload corpus JSON")
    parser.add_argument("--target-id", default=None, help="Identifier for dynamic target")
    parser.add_argument("--name", default=None, help="Display name for dynamic target")
    parser.add_argument("--proxy", default=None, help="Upstream HTTP/HTTPS proxy URL (e.g. http://127.0.0.1:8080)")
    parser.add_argument("--insecure", "-k", action="store_true", help="Disable SSL certificate verification")
    parser.add_argument("--verify-tokens", action="store_true", help="Audit protected endpoints for RFC 7519 Broken Authentication")
    parser.add_argument("--verify-callbacks", action="store_true", help="Audit endpoints for loopback/SSRF callback vulnerabilities")
    parser.add_argument("--callback-url", default=None, help="External canary callback URL for OOB SSRF detection")
    parser.add_argument("--save-profile", action="store_true", help="Save dynamic target to targets/profiles/ for reuse")
    parser.add_argument("--report", action="store_true", help="Generate and open the latest HTML report in browser")
    parser.add_argument("--sarif", action="store_true", help="Generate and export the latest findings to OASIS SARIF format")
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

    if args.sarif:
        reporter = SecurityReporter(RESULTS.results_dir)
        findings = reporter.load_findings()
        if not findings:
            print("[!] No findings found in results/ to generate SARIF.")
            return 1
        sarif_file = reporter.generate_sarif_report(findings)
        print(f"[+] SARIF report generated at: {sarif_file}")
        print(f"[+] Updated: {RESULTS.results_dir / 'vulnerabilities.sarif'}")
        return 0

    if args.workflow:
        return run_workflow(
            args.workflow,
            base_url=args.url,
            proxy=args.proxy,
            insecure=args.insecure,
        )

    if args.url and not args.interactive:
        kwargs: dict[str, Any] = {
            "url": args.url,
            "schema": args.schema,
            "auth_token": args.auth_token,
            "protocol": args.protocol,
            "endpoint": args.endpoint,
            "payloads": args.payloads,
            "target_id": args.target_id,
            "name": args.name,
        }
        if args.save_profile:
            kwargs["save_profile"] = True
        if args.postman:
            kwargs["postman"] = args.postman
        if args.har:
            kwargs["har"] = args.har
        if args.proxy:
            kwargs["proxy"] = args.proxy
        if args.insecure:
            kwargs["insecure"] = args.insecure
        if args.verify_tokens:
            kwargs["verify_tokens"] = args.verify_tokens
        if args.verify_callbacks:
            kwargs["verify_callbacks"] = args.verify_callbacks
        if args.callback_url:
            kwargs["callback_url"] = args.callback_url
        return run_dynamic_target(**kwargs)

    # Interactive terminal website mode
    return interactive_terminal_ui()


if __name__ == "__main__":
    raise SystemExit(main())
