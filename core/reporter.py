"""Security reporting module: Terminal dashboard, HTML report, and SARIF exporter."""

from __future__ import annotations

import csv
import hashlib
import hmac
import json
import logging
import os
import re
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from .path_manager import ProjectPaths
from .report_templates import render_html_document
from .sarif_exporter import build_sarif_document

PROJECT_ROOT = Path(__file__).resolve().parents[1]
logger = logging.getLogger(__name__)
_DEFAULT_SIGNING_KEY = "Schemathesis-Default-Audit-Key-2026"


def compute_tamper_signature(content: str, secret_key: Optional[str] = None) -> str:
    """Compute HMAC-SHA256 signature for tamper-evident reporting."""
    env_key = os.environ.get("REPORT_SIGNING_KEY")
    if secret_key is None and not env_key:
        logger.debug("REPORT_SIGNING_KEY is unset; signing with default development audit key.")
    key = (secret_key or env_key or _DEFAULT_SIGNING_KEY).encode("utf-8")
    return hmac.new(key, content.encode("utf-8"), hashlib.sha256).hexdigest()


# Reconfigure stdout to UTF-8 if supported to prevent Windows charmap encoding errors
try:
    if sys.stdout and hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, OSError) as exc:
    logger.debug("stdout UTF-8 reconfigure skipped: %s", exc)

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
    "critical": ("\033[91m\033[1m", "#ef4444"),
    "high": ("\033[31m", "#f97316"),
    "medium": ("\033[33m", "#eab308"),
    "low": ("\033[34m", "#3b82f6"),
    "info": ("\033[90m", "#64748b"),
}


def _safe_print(text: str) -> None:
    try:
        print(text)
    except UnicodeEncodeError:
        clean = text.encode("ascii", errors="replace").decode("ascii")
        print(clean)


class SecurityReporter:
    """Consolidates findings and produces executive terminal dashboards, HTML reports, and SARIF."""

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
            except Exception as exc:
                logger.warning("Failed to read NDJSON findings from %s: %s", ndjson_path, exc)

        if not findings and csv_path.exists() and csv_path.stat().st_size > 0:
            try:
                with csv_path.open("r", newline="", encoding="utf-8-sig") as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        if run_id and row.get("run_id") != run_id:
                            continue
                        findings.append(self._normalize_finding(dict(row)))
            except Exception as exc:
                logger.warning("Failed to read CSV findings from %s: %s", csv_path, exc)

        if limit is not None and limit > 0:
            findings = findings[-limit:]

        return findings

    def load_latest_findings(self) -> list[dict[str, Any]]:
        """Load findings from the most recent test run."""
        all_findings = self.load_findings()
        if not all_findings:
            return []

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
            except (json.JSONDecodeError, TypeError):
                logger.debug("Leaving non-JSON payload string unparsed during report normalization.")

        evidence = raw.get("evidence")
        if isinstance(evidence, dict):
            evidence_str = json.dumps(evidence, ensure_ascii=False)
        else:
            evidence_str = str(evidence or "")

        owasp = raw.get("owasp_category")
        if owasp:
            match = re.search(r"API\d+:2023", str(owasp))
            owasp = match.group(0) if match else str(owasp).strip()
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

        matched_cve = raw.get("matched_cve") or raw.get("cve_matches") or []
        if isinstance(matched_cve, str):
            matched_cve = [c.strip() for c in matched_cve.split(",") if c.strip()]

        observations_raw = raw.get("observations")
        observations: list[dict[str, Any]] = []
        if isinstance(observations_raw, list):
            observations = [o for o in observations_raw if isinstance(o, dict)]
        elif isinstance(observations_raw, str) and observations_raw.strip():
            try:
                parsed_obs = json.loads(observations_raw)
                if isinstance(parsed_obs, list):
                    observations = [o for o in parsed_obs if isinstance(o, dict)]
            except (json.JSONDecodeError, TypeError):
                observations = []

        try:
            observation_count = int(raw.get("observation_count") or len(observations) or 0)
        except (ValueError, TypeError):
            observation_count = len(observations)

        try:
            error_count = int(raw.get("error_count") or 0)
        except (ValueError, TypeError):
            error_count = 0

        lifecycle = str(raw.get("lifecycle") or ("confirmed" if confirmed else "unknown")).strip().lower()

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
            "lifecycle": lifecycle,
            "fingerprint": str(raw.get("fingerprint") or ""),
            "matched_cve": matched_cve,
            "curl_command": raw.get("curl_command") or "",
            "observations": observations,
            "observation_count": observation_count,
            "error_count": error_count,
        }

    def _infer_target_info(
        self,
        findings: list[dict[str, Any]],
        target_info: dict[str, Any] | None = None,
    ) -> dict[str, str]:
        """Resolve target name, base URL, apps, run ID, and schema for reports."""
        info = dict(target_info or {})
        apps = list(dict.fromkeys(
            str(f.get("target_app") or "").strip()
            for f in findings
            if str(f.get("target_app") or "").strip() not in {"", "default"}
        ))
        run_ids = list(dict.fromkeys(
            str(f.get("run_id") or "").strip()
            for f in findings
            if str(f.get("run_id") or "").strip()
        ))

        inferred_url = str(info.get("url") or "").strip()
        inferred_schema = str(info.get("schema") or info.get("schema_file") or info.get("schema_path") or "").strip()
        inferred_protocol = str(info.get("protocol") or "").strip().upper()

        # Try reading manifest.json from latest run directory
        if run_ids:
            manifest_path = self.results_dir / run_ids[-1] / "manifest.json"
            if manifest_path.is_file():
                try:
                    m_data = json.loads(manifest_path.read_text(encoding="utf-8"))
                    target_desc = str(m_data.get("target") or "").strip()
                    if target_desc and not inferred_schema and "=" in target_desc:
                        _, _, rhs = target_desc.partition("=")
                        inferred_schema = rhs.strip()
                    meta = m_data.get("metadata") or {}
                    if not inferred_protocol and meta.get("tool"):
                        inferred_protocol = "GraphQL" if meta["tool"] == "graphql" else "REST"
                except Exception as exc:
                    logger.debug("Could not inspect run manifest %s: %s", manifest_path, exc)

        # Infer base URL from curl_command or target_app name if not supplied
        if not inferred_url:
            urls_found: list[str] = []
            for f in findings:
                cmd = str(f.get("curl_command") or "")
                m_url = re.search(r"https?://[^\s'\"\\]+", cmd)
                if m_url:
                    from urllib.parse import urlparse
                    parsed = urlparse(m_url.group(0))
                    if parsed.scheme and parsed.netloc:
                        base = f"{parsed.scheme}://{parsed.netloc}"
                        if base not in urls_found:
                            urls_found.append(base)
            if urls_found:
                inferred_url = ", ".join(urls_found[:3])

        # Fallback: look up saved target profiles when URL or name is still missing
        if (not inferred_url or not info.get("name")) and apps:
            try:
                from .target_manager import TargetManager
                tm = TargetManager(PROJECT_ROOT)
                matched_urls: list[str] = []
                matched_names: list[str] = []
                for app in apps:
                    t_cfg = tm.targets.get(app)
                    if t_cfg:
                        if t_cfg.base_url and t_cfg.base_url not in matched_urls:
                            matched_urls.append(t_cfg.base_url)
                        if t_cfg.name and t_cfg.name not in matched_names:
                            matched_names.append(t_cfg.name)
                if not inferred_url and matched_urls:
                    inferred_url = ", ".join(matched_urls[:3])
                if not info.get("name") and matched_names:
                    info["name"] = ", ".join(matched_names[:3])
            except Exception as exc:
                logger.debug("Target profile lookup during report generation skipped: %s", exc)

        inferred_name = str(info.get("name") or "").strip()
        if not inferred_name:
            if apps:
                inferred_name = ", ".join(apps[:3]) + (f" (+{len(apps) - 3})" if len(apps) > 3 else "")
            elif inferred_url:
                inferred_name = inferred_url
            else:
                inferred_name = "API Security Fuzzing"

        return {
            "name": inferred_name,
            "url": inferred_url or "Not specified",
            "apps": ", ".join(apps) if apps else inferred_name,
            "run_id": run_ids[-1] if run_ids else "N/A",
            "schema": inferred_schema or "N/A",
            "protocol": inferred_protocol or "API",
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
        endpoints = len({(f.get("method"), f.get("endpoint")) for f in findings})

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
        """Generate a standalone interactive HTML report with zero external dependencies."""
        metrics = self.compute_metrics(findings)
        resolved_target = self._infer_target_info(findings, target_info)
        target_name = resolved_target["name"]
        target_url = resolved_target["url"]
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        self.results_dir.mkdir(parents=True, exist_ok=True)
        if output_file is not None:
            report_path = Path(output_file).resolve()
        else:
            ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            report_path = self.results_dir / f"report_{ts}.html"

        html_content = render_html_document(
            findings,
            metrics,
            target_name=target_name,
            target_url=target_url,
            target_meta=resolved_target,
            now_str=now_str,
            owasp_metadata=OWASP_METADATA,
            severity_colors=SEVERITY_COLORS,
        )

        sig = compute_tamper_signature(html_content)
        footer_badge = f"""
        <footer style="margin-top: 40px; padding: 20px; border-top: 1px solid #334155; text-align: center; font-size: 13px; color: #94a3b8;">
            <div>🛡️ <strong>Tamper-Evident Security Audit Seal</strong></div>
            <div style="font-family: monospace; margin-top: 6px; word-break: break-all;">
                HMAC-SHA256: {sig}
            </div>
        </footer>
        <!-- INTEGRITY_SIGNATURE: alg=HMAC-SHA256, signature={sig} -->
        """
        html_content = html_content.replace("</body>", f"{footer_badge}\n</body>")
        report_path.write_text(html_content, encoding="utf-8")

        latest_path = self.results_dir / "latest_report.html"
        try:
            shutil.copy2(report_path, latest_path)
        except OSError as exc:
            logger.warning("Failed to update %s: %s", latest_path, exc)

        try:
            self.generate_sarif_report(findings, target_info)
        except Exception as exc:
            logger.warning("Failed to generate paired SARIF report: %s", exc)

        return report_path

    def generate_sarif_report(
        self,
        findings: list[dict[str, Any]],
        target_info: dict[str, Any] | None = None,
        output_file: str | Path | None = None,
    ) -> Path:
        """Generate an industry-standard OASIS SARIF v2.1.0 report for DevSecOps/CI-CD."""
        self.results_dir.mkdir(parents=True, exist_ok=True)
        if output_file:
            sarif_path = self.paths.resolve(output_file, allow_outside=True)
        else:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            sarif_path = self.results_dir / f"report_{timestamp}.sarif"

        sarif_doc = build_sarif_document(
            findings,
            owasp_metadata=OWASP_METADATA,
            project_root=PROJECT_ROOT,
            sign_fn=compute_tamper_signature,
            target_info=target_info,
        )

        sarif_path.write_text(json.dumps(sarif_doc, indent=2, ensure_ascii=False), encoding="utf-8")
        canonical_sarif = self.results_dir / "vulnerabilities.sarif"
        try:
            shutil.copy2(sarif_path, canonical_sarif)
        except OSError as exc:
            logger.warning("Failed to update %s: %s", canonical_sarif, exc)

        return sarif_path


__all__ = ["SecurityReporter", "OWASP_METADATA", "compute_tamper_signature"]
