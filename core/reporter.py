"""Security reporting module: Terminal dashboard and interactive HTML report generator."""

from __future__ import annotations

import csv
import html
import json
import os
import re
import shutil
import sys
import webbrowser
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from .path_manager import ProjectPaths

PROJECT_ROOT = Path(__file__).resolve().parents[1]

# Reconfigure stdout to utf-8 if supported to prevent Windows charmap encoding errors
try:
    if sys.stdout and hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

# OWASP API Security Top 10 (2023) Metadata & Remediation Guidance
OWASP_METADATA = {
    "API1:2023": {
        "name": "Broken Object Level Authorization (BOLA / IDOR)",
        "remediation": "Enforce strict user-to-resource ownership validation at the data-access layer. Never trust client-provided object IDs without verifying the user's session rights.",
    },
    "API2:2023": {
        "name": "Broken Authentication",
        "remediation": "Enforce strong password policies, secure JWT validation with expiration, rate-limit login endpoints, and implement multi-factor authentication (MFA).",
    },
    "API3:2023": {
        "name": "Broken Object Property Level Authorization",
        "remediation": "Use Data Transfer Objects (DTOs) and strict schema whitelisting. Prevent mass-assignment by explicitly rejecting unauthorized properties in request bodies.",
    },
    "API4:2023": {
        "name": "Unrestricted Resource Consumption",
        "remediation": "Apply rate limiting, request size quotas, query depth limits (GraphQL), and enforce pagination boundaries with maximum allowable limits.",
    },
    "API5:2023": {
        "name": "Broken Function Level Authorization (BFLA)",
        "remediation": "Implement granular role-based access control (RBAC) middleware. Ensure administrative endpoints verify user privileges before execution.",
    },
    "API6:2023": {
        "name": "Unrestricted Access to Sensitive Business Flows",
        "remediation": "Identify business-critical flows (e.g. coupon redemption, booking, checkout) and enforce velocity checks, CAPTCHA, and sequence validation.",
    },
    "API7:2023": {
        "name": "Server Side Request Forgery (SSRF)",
        "remediation": "Validate, sanitize, and restrict target URLs against a strict whitelist. Block loopback, link-local, and private cloud metadata IP ranges.",
    },
    "API8:2023": {
        "name": "Security Misconfiguration",
        "remediation": "Sanitize all user inputs to prevent injection (SQLi, Command Injection). Disable debug error outputs, verbose stack traces, and unneeded HTTP methods.",
    },
    "API9:2023": {
        "name": "Improper Inventory Management",
        "remediation": "Maintain an up-to-date API inventory. Deprecate and dismantle legacy/shadow API versions and ensure all exposed routes match OpenAPI specifications.",
    },
    "API10:2023": {
        "name": "Unsafe Consumption of APIs",
        "remediation": "Validate, sanitize, and inspect all payloads returned by third-party external services before forwarding or processing in backend components.",
    },
}

SEVERITY_COLORS = {
    "critical": ("\033[91m\033[1m", "#ef4444"),  # Red bold
    "high": ("\033[31m", "#f97316"),            # Red/Orange
    "medium": ("\033[33m", "#eab308"),          # Yellow
    "low": ("\033[34m", "#3b82f6"),             # Blue
    "info": ("\033[90m", "#64748b"),            # Gray
}
RESET_COLOR = "\033[0m"


def _safe_print(text: str) -> None:
    try:
        print(text)
    except UnicodeEncodeError:
        # Fallback to ascii replacement if terminal does not support unicode
        clean = text.encode("ascii", errors="replace").decode("ascii")
        print(clean)


class SecurityReporter:
    """Consolidates findings and produces executive terminal dashboards and interactive HTML reports."""

    def __init__(self, results_dir: str | Path | None = None):
        self.paths = ProjectPaths.from_root(PROJECT_ROOT)
        self.results_dir = (
            self.paths.results
            if results_dir is None
            else self.paths.resolve(results_dir, allow_outside=True)
        )

    def load_findings(
        self,
        *,
        run_id: str | None = None,
        limit: int | None = None,
    ) -> list[dict[str, Any]]:
        """Load findings from vulnerabilities.ndjson or vulnerabilities.csv."""
        findings: list[dict[str, Any]] = []
        ndjson_path = self.results_dir / "vulnerabilities.ndjson"
        csv_path = self.results_dir / "vulnerabilities.csv"

        if ndjson_path.exists() and ndjson_path.stat().st_size > 0:
            try:
                for line in ndjson_path.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                        if run_id and record.get("run_id") != run_id:
                            continue
                        findings.append(self._normalize_finding(record))
                    except json.JSONDecodeError:
                        continue
            except Exception:
                pass

        if not findings and csv_path.exists() and csv_path.stat().st_size > 0:
            try:
                with csv_path.open("r", newline="", encoding="utf-8-sig") as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        if run_id and row.get("run_id") != run_id:
                            continue
                        findings.append(self._normalize_finding(dict(row)))
            except Exception:
                pass

        if limit is not None and limit > 0:
            findings = findings[-limit:]

        return findings

    def load_latest_findings(self) -> list[dict[str, Any]]:
        """Load findings from the most recent test run."""
        all_findings = self.load_findings()
        if not all_findings:
            return []

        # Find the latest run_id from findings
        latest_run_id = all_findings[-1].get("run_id")
        if latest_run_id:
            latest = [f for f in all_findings if f.get("run_id") == latest_run_id]
            if latest:
                return latest
        return all_findings

    def _normalize_finding(self, raw: dict[str, Any]) -> dict[str, Any]:
        """Normalize finding fields across different runner versions."""
        severity = str(raw.get("severity") or "info").lower().strip()
        if severity not in SEVERITY_COLORS:
            severity = "info"

        confirmed_raw = raw.get("confirmed")
        if isinstance(confirmed_raw, str):
            confirmed = confirmed_raw.lower() in {"true", "1", "yes"}
        else:
            confirmed = bool(confirmed_raw)

        payload = raw.get("payload")
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except Exception:
                pass

        evidence = raw.get("evidence")
        if isinstance(evidence, dict):
            evidence_str = json.dumps(evidence, ensure_ascii=False)
        else:
            evidence_str = str(evidence or "")

        owasp = raw.get("owasp_category")
        if owasp:
            match = re.search(r"API\d+:2023", str(owasp))
            if match:
                owasp = match.group(0)
            else:
                owasp = str(owasp).strip()
        else:
            owasp = "Unassigned"

        response_time = raw.get("response_time_ms")
        try:
            response_time = float(response_time) if response_time is not None else None
        except (ValueError, TypeError):
            response_time = None

        status_code = raw.get("status_code")
        try:
            status_code = int(status_code) if status_code is not None else None
        except (ValueError, TypeError):
            status_code = None

        matched_cve = raw.get("matched_cve") or []
        if isinstance(matched_cve, str):
            matched_cve = [c.strip() for c in matched_cve.split(",") if c.strip()]

        return {
            "finding_id": str(raw.get("finding_id") or raw.get("fingerprint") or ""),
            "run_id": str(raw.get("run_id") or ""),
            "timestamp": str(raw.get("timestamp") or ""),
            "target_app": str(raw.get("target_app") or "default"),
            "endpoint": str(raw.get("endpoint") or "/"),
            "method": str(raw.get("method") or "GET").upper(),
            "attack_type": str(raw.get("attack_type") or "UNKNOWN"),
            "owasp_category": owasp,
            "payload": payload,
            "status_code": status_code,
            "response_time_ms": response_time,
            "evidence": evidence_str,
            "severity": severity,
            "confirmed": confirmed,
            "fingerprint": str(raw.get("fingerprint") or ""),
            "matched_cve": matched_cve,
        }

    def compute_metrics(self, findings: list[dict[str, Any]]) -> dict[str, Any]:
        """Compute statistical breakdown for dashboard display."""
        total = len(findings)
        confirmed_count = sum(1 for f in findings if f.get("confirmed"))

        severity_counts = {k: 0 for k in ("critical", "high", "medium", "low", "info")}
        for f in findings:
            sev = f.get("severity", "info")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        owasp_counts: dict[str, int] = {}
        for f in findings:
            cat = f.get("owasp_category") or "Unassigned"
            owasp_counts[cat] = owasp_counts.get(cat, 0) + 1

        valid_times = [f["response_time_ms"] for f in findings if f.get("response_time_ms") is not None]
        avg_latency = round(sum(valid_times) / len(valid_times), 1) if valid_times else 0.0

        endpoints = len(set((f.get("method"), f.get("endpoint")) for f in findings))

        return {
            "total": total,
            "confirmed": confirmed_count,
            "severity_counts": severity_counts,
            "owasp_counts": dict(sorted(owasp_counts.items(), key=lambda x: x[1], reverse=True)),
            "avg_latency_ms": avg_latency,
            "unique_endpoints": endpoints,
        }

    def render_terminal_dashboard(
        self,
        findings: list[dict[str, Any]],
        target_info: dict[str, Any] | None = None,
    ) -> None:
        """Render a terminal dashboard with ANSI colors and box-drawing."""
        metrics = self.compute_metrics(findings)
        target_name = (target_info or {}).get("name") or "API Security Target"
        target_url = (target_info or {}).get("url") or "Configured Profile"

        _safe_print("")
        _safe_print("\033[1;36m" + "╔" + "═" * 74 + "╗")
        _safe_print("║" + "   🛡️   API SECURITY FUZZING EXECUTIVE REPORT & DASHBOARD   🛡️   ".center(74) + "║")
        _safe_print("╚" + "═" * 74 + "╝\033[0m")
        _safe_print(f" \033[1mTarget:\033[0m {target_name} ({target_url})")
        _safe_print(f" \033[1mReport Generated:\033[0m {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        _safe_print("")

        # Key Metrics KPI Cards
        sev = metrics["severity_counts"]
        confirmed_color = "\033[1;91m" if metrics["confirmed"] > 0 else "\033[1;32m"
        _safe_print(" \033[1mEXECUTIVE SUMMARY\033[0m")
        _safe_print(" ┌" + "─" * 16 + "┬" + "─" * 18 + "┬" + "─" * 18 + "┬" + "─" * 18 + "┐")
        _safe_print(
            f" │ Total Findings │ Confirmed Bugs    │ Critical / High  │ Avg Latency (ms) │\n"
            f" │ {metrics['total']:^14} │ {confirmed_color}{metrics['confirmed']:^16}\033[0m │ "
            f"\033[1;91m{sev['critical'] + sev['high']:^16}\033[0m │ {metrics['avg_latency_ms']:^16} │"
        )
        _safe_print(" └" + "─" * 16 + "┴" + "─" * 18 + "┴" + "─" * 18 + "┴" + "─" * 18 + "┘")
        _safe_print("")

        # Severity Breakdown Pills
        _safe_print(" \033[1mSEVERITY DISTRIBUTION\033[0m")
        pills = [
            f"\033[1;91m[CRITICAL: {sev['critical']}]\033[0m",
            f"\033[1;31m[HIGH: {sev['high']}]\033[0m",
            f"\033[1;33m[MEDIUM: {sev['medium']}]\033[0m",
            f"\033[1;34m[LOW: {sev['low']}]\033[0m",
            f"\033[90m[INFO: {sev['info']}]\033[0m",
        ]
        _safe_print("   " + "   ".join(pills))
        _safe_print("")

        # OWASP Top 10 Breakdown Table
        if metrics["owasp_counts"]:
            _safe_print(" \033[1mOWASP API SECURITY TOP 10 (2023) BREAKDOWN\033[0m")
            _safe_print(" ┌" + "─" * 12 + "┬" + "─" * 44 + "┬" + "─" * 8 + "┬" + "─" * 11 + "┐")
            _safe_print(" │ Category   │ Name                                         │ Total  │ Confirmed │")
            _safe_print(" ├" + "─" * 12 + "┼" + "─" * 44 + "┼" + "─" * 8 + "┼" + "─" * 11 + "┤")
            for cat, count in metrics["owasp_counts"].items():
                meta = OWASP_METADATA.get(cat, {})
                name = meta.get("name", cat)
                if len(name) > 42:
                    name = name[:39] + "..."
                cat_confirmed = sum(1 for f in findings if f.get("owasp_category") == cat and f.get("confirmed"))
                conf_str = f"\033[91m{cat_confirmed:^9}\033[0m" if cat_confirmed > 0 else f"{cat_confirmed:^9}"
                _safe_print(f" │ {cat:<10} │ {name:<42} │ {count:^6} │ {conf_str} │")
            _safe_print(" └" + "─" * 12 + "┴" + "─" * 44 + "┴" + "─" * 8 + "┴" + "─" * 11 + "┘")
            _safe_print("")

        # Highlight Confirmed Vulnerabilities
        confirmed_findings = [f for f in findings if f.get("confirmed")]
        if confirmed_findings:
            _safe_print(" \033[1;91m🚨 VERIFIED / CONFIRMED VULNERABILITIES (PROOF OF EXPLOIT)\033[0m")
            _safe_print(" ┌" + "─" * 8 + "┬" + "─" * 28 + "┬" + "─" * 18 + "┬" + "─" * 16 + "┐")
            _safe_print(" │ Method │ Endpoint                   │ Attack Type      │ Severity       │")
            _safe_print(" ├" + "─" * 8 + "┼" + "─" * 28 + "┼" + "─" * 18 + "┼" + "─" * 16 + "┤")
            for f in confirmed_findings[:15]:
                ep = f["endpoint"]
                if len(ep) > 26:
                    ep = ep[:23] + "..."
                attack = f["attack_type"]
                if len(attack) > 16:
                    attack = attack[:14] + ".."
                color, _ = SEVERITY_COLORS.get(f["severity"], ("", ""))
                sev_label = f"{color}{f['severity'].upper():<14}\033[0m"
                _safe_print(f" │ {f['method']:<6} │ {ep:<26} │ {attack:<16} │ {sev_label} │")
            _safe_print(" └" + "─" * 8 + "┴" + "─" * 28 + "┴" + "─" * 18 + "┴" + "─" * 16 + "┘")
            if len(confirmed_findings) > 15:
                _safe_print(f"   ... and {len(confirmed_findings) - 15} more verified vulnerabilities.")
            _safe_print("")
        else:
            _safe_print(" \033[1;32m[+] No confirmed exploits found in this run.\033[0m\n")

    def generate_html_report(
        self,
        findings: list[dict[str, Any]],
        target_info: dict[str, Any] | None = None,
        output_file: str | Path | None = None,
    ) -> Path:
        """Generate a modern, interactive single-file HTML report with zero external dependencies."""
        metrics = self.compute_metrics(findings)
        target_name = (target_info or {}).get("name") or "API Security Fuzzing"
        target_url = (target_info or {}).get("url") or "Target Endpoint"
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        # Determine output file path
        self.results_dir.mkdir(parents=True, exist_ok=True)
        if output_file is not None:
            report_path = Path(output_file).resolve()
        else:
            ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            report_path = self.results_dir / f"report_{ts}.html"

        # Generate findings rows
        findings_html = []
        for index, f in enumerate(findings, start=1):
            sev = f["severity"].lower()
            _, hex_color = SEVERITY_COLORS.get(sev, ("", "#64748b"))
            is_confirmed = f["confirmed"]
            confirmed_badge = (
                '<span class="badge badge-confirmed">CONFIRMED VULNERABILITY</span>'
                if is_confirmed
                else '<span class="badge badge-unconfirmed">PROBE / UNCONFIRMED</span>'
            )
            sev_badge = f'<span class="badge" style="background-color: {hex_color}22; color: {hex_color}; border: 1px solid {hex_color}55;">{sev.upper()}</span>'

            # Payload format
            raw_payload = f.get("payload")
            if isinstance(raw_payload, (dict, list)):
                payload_str = json.dumps(raw_payload, indent=2, ensure_ascii=False)
            else:
                payload_str = str(raw_payload or "")

            # Remediation
            owasp_cat = f.get("owasp_category") or ""
            remediation = OWASP_METADATA.get(owasp_cat, {}).get(
                "remediation",
                "Ensure inputs are validated against schema, enforce authentication/authorization checks, and sanitize responses.",
            )

            cve_badges = "".join(
                f'<span class="cve-tag">{html.escape(c)}</span>'
                for c in (f.get("matched_cve") or [])
            ) or '<span style="color: #64748b;">None</span>'

            findings_html.append(f"""
            <div class="finding-card severity-{sev} {'is-confirmed' if is_confirmed else ''}" data-severity="{sev}" data-confirmed="{str(is_confirmed).lower()}">
                <div class="finding-header" onclick="toggleDetails('{index}')">
                    <div class="finding-title">
                        <span class="method-tag method-{html.escape(f['method'])}">{html.escape(f['method'])}</span>
                        <span class="endpoint-name">{html.escape(f['endpoint'])}</span>
                        {sev_badge}
                        {confirmed_badge}
                    </div>
                    <div class="finding-meta">
                        <span class="status-code">HTTP {f.get('status_code') or '---'}</span>
                        <span class="latency">{f.get('response_time_ms') or 0} ms</span>
                        <span class="expand-icon" id="icon-{index}">▼</span>
                    </div>
                </div>
                <div class="finding-details" id="details-{index}" style="display: none;">
                    <div class="detail-grid">
                        <div class="detail-box">
                            <h4>Attack Details</h4>
                            <p><strong>Attack Type:</strong> {html.escape(f['attack_type'])}</p>
                            <p><strong>OWASP Category:</strong> {html.escape(owasp_cat)} - {html.escape(OWASP_METADATA.get(owasp_cat, {}).get('name', 'N/A'))}</p>
                            <p><strong>Matched CVEs:</strong> {cve_badges}</p>
                            <p><strong>Fingerprint:</strong> <code>{html.escape(f.get('fingerprint', ''))}</code></p>
                        </div>
                        <div class="detail-box">
                            <h4>Evidence / Signal</h4>
                            <pre class="evidence-box">{html.escape(f.get('evidence') or 'No signal detected')}</pre>
                        </div>
                    </div>

                    <div class="detail-box full-width">
                        <h4>Fuzzing Payload</h4>
                        <pre class="code-box"><code>{html.escape(payload_str)}</code></pre>
                    </div>

                    <div class="remediation-box">
                        <strong>🛡️ Recommended Remediation:</strong>
                        <p>{html.escape(remediation)}</p>
                    </div>
                </div>
            </div>
            """)

        all_findings_str = "\n".join(findings_html) if findings_html else "<div class='empty-state'>No security findings recorded. Target is clean!</div>"

        # OWASP Bar Chart SVG
        owasp_bars = []
        max_owasp = max(metrics["owasp_counts"].values()) if metrics["owasp_counts"] else 1
        for cat, cnt in list(metrics["owasp_counts"].items())[:7]:
            pct = int((cnt / max_owasp) * 100)
            meta_name = OWASP_METADATA.get(cat, {}).get("name", cat)
            owasp_bars.append(f"""
            <div class="bar-row">
                <span class="bar-label">{html.escape(cat)} - {html.escape(meta_name)} ({cnt})</span>
                <div class="bar-container">
                    <div class="bar-fill" style="width: {pct}%;"></div>
                </div>
            </div>
            """)
        owasp_bars_html = "\n".join(owasp_bars) or "<p class='text-muted'>No OWASP categories detected.</p>"

        # SVG Donut Chart for Severity
        sev_counts = metrics["severity_counts"]
        total_sev = max(1, sum(sev_counts.values()))
        crit_pct = round((sev_counts["critical"] / total_sev) * 100)
        high_pct = round((sev_counts["high"] / total_sev) * 100)
        med_pct = round((sev_counts["medium"] / total_sev) * 100)
        low_pct = round((sev_counts["low"] / total_sev) * 100)

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>API Security Report - {html.escape(target_name)}</title>
    <style>
        :root {{
            --bg-primary: #0a0e17;
            --bg-secondary: #121824;
            --bg-card: #182232;
            --text-primary: #f1f5f9;
            --text-secondary: #94a3b8;
            --border: #223249;
            --accent: #38bdf8;
            --critical: #ef4444;
            --high: #f97316;
            --medium: #eab308;
            --low: #3b82f6;
            --info: #64748b;
            --success: #10b981;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background-color: var(--bg-primary);
            color: var(--text-primary);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            line-height: 1.5;
            padding: 24px;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding-bottom: 20px;
            border-bottom: 1px solid var(--border);
            margin-bottom: 24px;
        }}
        .brand h1 {{ font-size: 24px; font-weight: 700; color: #fff; display: flex; align-items: center; gap: 8px; }}
        .brand p {{ color: var(--text-secondary); font-size: 14px; }}
        .header-actions button {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            color: var(--text-primary);
            padding: 8px 16px;
            border-radius: 6px;
            cursor: pointer;
            font-weight: 500;
        }}
        .header-actions button:hover {{ background: #1e2d42; }}

        /* KPI Cards */
        .kpi-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }}
        .kpi-card {{
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 18px;
        }}
        .kpi-title {{ font-size: 13px; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.5px; }}
        .kpi-value {{ font-size: 32px; font-weight: 700; margin-top: 6px; }}
        .kpi-value.danger {{ color: var(--critical); }}
        .kpi-value.warning {{ color: var(--high); }}
        .kpi-value.clean {{ color: var(--success); }}

        /* Chart section */
        .analytics-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 16px;
            margin-bottom: 24px;
        }}
        .chart-box {{
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 20px;
        }}
        .chart-box h3 {{ font-size: 16px; margin-bottom: 16px; color: var(--text-primary); }}

        .bar-row {{ margin-bottom: 10px; }}
        .bar-label {{ font-size: 12px; color: var(--text-secondary); display: block; margin-bottom: 4px; }}
        .bar-container {{ width: 100%; background: #1e293b; height: 10px; border-radius: 5px; overflow: hidden; }}
        .bar-fill {{ background: var(--accent); height: 100%; border-radius: 5px; }}

        /* Controls */
        .controls {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 16px;
            flex-wrap: wrap;
            gap: 12px;
        }}
        .filter-group {{ display: flex; gap: 8px; flex-wrap: wrap; }}
        .filter-btn {{
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            color: var(--text-secondary);
            padding: 6px 12px;
            border-radius: 6px;
            font-size: 13px;
            cursor: pointer;
        }}
        .filter-btn.active {{
            background: var(--accent);
            color: #04101d;
            font-weight: 600;
            border-color: var(--accent);
        }}
        .search-input {{
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            color: var(--text-primary);
            padding: 8px 14px;
            border-radius: 6px;
            width: 280px;
        }}

        /* Findings Cards */
        .finding-card {{
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 8px;
            margin-bottom: 10px;
            overflow: hidden;
            transition: border-color 0.2s;
        }}
        .finding-card.is-confirmed {{ border-left: 4px solid var(--critical); }}
        .finding-header {{
            padding: 14px 18px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
            user-select: none;
        }}
        .finding-header:hover {{ background: rgba(255, 255, 255, 0.02); }}
        .finding-title {{ display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }}
        .method-tag {{
            font-size: 12px;
            font-weight: 700;
            padding: 2px 8px;
            border-radius: 4px;
            background: #334155;
        }}
        .method-GET {{ background: #0369a1; color: #e0f2fe; }}
        .method-POST {{ background: #15803d; color: #dcfce7; }}
        .method-DELETE {{ background: #b91c1c; color: #fee2e2; }}
        .method-PUT {{ background: #b45309; color: #fef3c7; }}
        .endpoint-name {{ font-family: monospace; font-size: 14px; font-weight: 600; }}

        .badge {{
            font-size: 11px;
            font-weight: 700;
            padding: 3px 8px;
            border-radius: 9999px;
            text-transform: uppercase;
        }}
        .badge-confirmed {{ background: rgba(239, 68, 68, 0.2); color: var(--critical); border: 1px solid rgba(239, 68, 68, 0.4); }}
        .badge-unconfirmed {{ background: rgba(100, 116, 139, 0.15); color: var(--text-secondary); }}

        .finding-meta {{ display: flex; align-items: center; gap: 14px; color: var(--text-secondary); font-size: 13px; }}
        .expand-icon {{ font-size: 10px; color: var(--text-secondary); }}

        .finding-details {{
            padding: 18px;
            border-top: 1px solid var(--border);
            background: #0d131f;
        }}
        .detail-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 16px;
            margin-bottom: 14px;
        }}
        .detail-box h4 {{ font-size: 13px; color: var(--text-secondary); text-transform: uppercase; margin-bottom: 8px; }}
        .detail-box p {{ font-size: 13px; margin-bottom: 6px; }}
        .cve-tag {{ background: #1e293b; padding: 2px 6px; border-radius: 4px; font-size: 11px; margin-right: 4px; }}

        .evidence-box, .code-box {{
            background: #070b12;
            padding: 12px;
            border-radius: 6px;
            font-family: monospace;
            font-size: 12px;
            overflow-x: auto;
            border: 1px solid #1a2536;
            color: #38bdf8;
            max-height: 250px;
        }}

        .remediation-box {{
            margin-top: 14px;
            background: rgba(56, 189, 248, 0.08);
            border: 1px solid rgba(56, 189, 248, 0.3);
            border-radius: 6px;
            padding: 12px 16px;
            font-size: 13px;
            color: #bae6fd;
        }}
        .empty-state {{ text-align: center; padding: 40px; color: var(--text-secondary); }}

        @media (max-width: 768px) {{
            .analytics-grid, .detail-grid {{ grid-template-columns: 1fr; }}
            .controls {{ flex-direction: column; align-items: stretch; }}
            .search-input {{ width: 100%; }}
        }}
        @media print {{
            body {{ background: #fff; color: #000; }}
            .finding-card {{ break-inside: avoid; border: 1px solid #ccc; }}
            .finding-details {{ display: block !important; }}
            .controls, .header-actions {{ display: none; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="brand">
                <h1>🛡️ API Security Fuzzing Report</h1>
                <p>Target: <strong>{html.escape(target_name)}</strong> ({html.escape(target_url)}) | Generated: {now_str}</p>
            </div>
            <div class="header-actions">
                <button onclick="window.print()">🖨️ Print / Save PDF</button>
            </div>
        </header>

        <section class="kpi-grid">
            <div class="kpi-card">
                <div class="kpi-title">Total Tests & Probes</div>
                <div class="kpi-value">{metrics['total']}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-title">Verified Exploits</div>
                <div class="kpi-value {'danger' if metrics['confirmed'] > 0 else 'clean'}">{metrics['confirmed']}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-title">Critical & High Vulnerabilities</div>
                <div class="kpi-value {'danger' if (sev_counts['critical'] + sev_counts['high']) > 0 else 'clean'}">
                    {sev_counts['critical'] + sev_counts['high']}
                </div>
            </div>
            <div class="kpi-card">
                <div class="kpi-title">Average Response Latency</div>
                <div class="kpi-value">{metrics['avg_latency_ms']} <span style="font-size: 16px; font-weight: normal;">ms</span></div>
            </div>
        </section>

        <section class="analytics-grid">
            <div class="chart-box">
                <h3>Severity Distribution</h3>
                <div class="bar-row">
                    <span class="bar-label">Critical ({sev_counts['critical']})</span>
                    <div class="bar-container"><div class="bar-fill" style="width: {crit_pct}%; background: var(--critical);"></div></div>
                </div>
                <div class="bar-row">
                    <span class="bar-label">High ({sev_counts['high']})</span>
                    <div class="bar-container"><div class="bar-fill" style="width: {high_pct}%; background: var(--high);"></div></div>
                </div>
                <div class="bar-row">
                    <span class="bar-label">Medium ({sev_counts['medium']})</span>
                    <div class="bar-container"><div class="bar-fill" style="width: {med_pct}%; background: var(--medium);"></div></div>
                </div>
                <div class="bar-row">
                    <span class="bar-label">Low ({sev_counts['low']})</span>
                    <div class="bar-container"><div class="bar-fill" style="width: {low_pct}%; background: var(--low);"></div></div>
                </div>
            </div>

            <div class="chart-box">
                <h3>OWASP API Security Top 10 (2023)</h3>
                {owasp_bars_html}
            </div>
        </section>

        <section>
            <div class="controls">
                <div class="filter-group">
                    <button class="filter-btn active" onclick="filterSeverity('all')">All ({metrics['total']})</button>
                    <button class="filter-btn" onclick="filterConfirmed()">Confirmed Only ({metrics['confirmed']})</button>
                    <button class="filter-btn" onclick="filterSeverity('critical')">Critical ({sev_counts['critical']})</button>
                    <button class="filter-btn" onclick="filterSeverity('high')">High ({sev_counts['high']})</button>
                    <button class="filter-btn" onclick="filterSeverity('medium')">Medium ({sev_counts['medium']})</button>
                    <button class="filter-btn" onclick="filterSeverity('low')">Low ({sev_counts['low']})</button>
                </div>
                <input type="text" class="search-input" id="searchInput" onkeyup="searchFindings()" placeholder="Search endpoint, attack, CVE...">
            </div>

            <div id="findingsContainer">
                {all_findings_str}
            </div>
        </section>
    </div>

    <script>
        function toggleDetails(id) {{
            const details = document.getElementById('details-' + id);
            const icon = document.getElementById('icon-' + id);
            if (details.style.display === 'none') {{
                details.style.display = 'block';
                icon.textContent = '▲';
            }} else {{
                details.style.display = 'none';
                icon.textContent = '▼';
            }}
        }}

        function filterSeverity(sev) {{
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            event.target.classList.add('active');
            const cards = document.querySelectorAll('.finding-card');
            cards.forEach(card => {{
                if (sev === 'all' || card.getAttribute('data-severity') === sev) {{
                    card.style.display = 'block';
                }} else {{
                    card.style.display = 'none';
                }}
            }});
        }}

        function filterConfirmed() {{
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            event.target.classList.add('active');
            const cards = document.querySelectorAll('.finding-card');
            cards.forEach(card => {{
                if (card.getAttribute('data-confirmed') === 'true') {{
                    card.style.display = 'block';
                }} else {{
                    card.style.display = 'none';
                }}
            }});
        }}

        function searchFindings() {{
            const query = document.getElementById('searchInput').value.toLowerCase();
            const cards = document.querySelectorAll('.finding-card');
            cards.forEach(card => {{
                const text = card.textContent.toLowerCase();
                if (text.includes(query)) {{
                    card.style.display = 'block';
                }} else {{
                    card.style.display = 'none';
                }}
            }});
        }}
    </script>
</body>
</html>
"""
        report_path.write_text(html_content, encoding="utf-8")

        # Also maintain a symlink / copy as 'latest_report.html' for instant access
        latest_path = self.results_dir / "latest_report.html"
        try:
            shutil.copy2(report_path, latest_path)
        except Exception:
            pass

        return report_path


__all__ = ["SecurityReporter", "OWASP_METADATA"]
