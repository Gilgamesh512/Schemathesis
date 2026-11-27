"""Standalone dark-themed HTML report template and card renderer."""

from __future__ import annotations

import html
import json
from typing import Any

from .curl_builder import build_curl_dual_from_finding
from .remediation_engine import RemediationEngine
from .validation_policy import sanitize_confidence


def render_finding_card(
    index: int,
    finding: dict[str, Any],
    *,
    target_url: str,
    owasp_metadata: dict[str, dict[str, str]],
    severity_colors: dict[str, tuple[str, str]],
) -> str:
    """Render one collapsible HTML card for a security finding."""
    sev = finding["severity"].lower()
    _, hex_color = severity_colors.get(sev, ("", "#64748b"))
    is_confirmed = bool(finding["confirmed"])
    lifecycle = str(
        finding.get("lifecycle") or finding.get("outcome") or ("confirmed" if is_confirmed else "unknown")
    ).strip().lower()
    confidence_val, _ = sanitize_confidence(finding.get("confidence"), default=0.0)
    confidence_pct = int(round(confidence_val * 100))

    lifecycle_badge_classes = {
        "confirmed": ("badge-confirmed", "CONFIRMED VULNERABILITY"),
        "candidate": ("badge-candidate", "CANDIDATE"),
        "inconclusive": ("badge-inconclusive", "INCONCLUSIVE"),
        "rejected": ("badge-rejected", "REJECTED"),
        "error": ("badge-error", "ERROR"),
    }
    badge_cls, badge_label = lifecycle_badge_classes.get(
        lifecycle,
        ("badge-inconclusive", html.escape(lifecycle.upper() or "UNKNOWN")),
    )
    confirmed_badge = f'<span class="badge {badge_cls}">{badge_label}</span>'
    sev_badge = (
        f'<span class="badge" style="background-color: {hex_color}22; '
        f'color: {hex_color}; border: 1px solid {hex_color}55;">{sev.upper()}</span>'
    )
    confidence_badge = f'<span class="confidence-tag">Confidence: {confidence_pct}%</span>'

    raw_payload = finding.get("payload")
    if isinstance(raw_payload, (dict, list)):
        payload_str = json.dumps(raw_payload, indent=2, ensure_ascii=False)
    else:
        payload_str = str(raw_payload or "")

    curl_dual = build_curl_dual_from_finding(finding, base_url=target_url)
    curl_bash = finding.get("curl_command") or curl_dual["bash"]
    curl_win_cmd = curl_dual["cmd"]

    owasp_cat = finding.get("owasp_category") or ""
    remediation = owasp_metadata.get(owasp_cat, {}).get(
        "remediation",
        "Ensure inputs are validated against schema, enforce authentication/authorization checks, and sanitize responses.",
    )

    snippet = RemediationEngine.get_snippet(owasp_cat)
    snippet_html = ""
    if snippet:
        snippet_html = f"""
                <div class="code-patch-box" style="margin-top: 10px; background: #0b1329; border: 1px solid #1e293b; border-radius: 6px; padding: 12px;">
                    <div style="font-weight: 600; color: #38bdf8; margin-bottom: 4px; font-size: 13px;">
                        🛠️ Idiomatic Fix Pattern ({html.escape(snippet.framework)}): {html.escape(snippet.title)}
                    </div>
                    <p style="font-size: 12px; color: #94a3b8; margin: 4px 0 8px 0;">{html.escape(snippet.explanation)}</p>
                    <div style="font-size: 11px; font-weight: 600; color: #4ade80; margin-bottom: 4px;">✓ Secure Implementation:</div>
                    <pre class="code-box" style="background: #020617; color: #4ade80; margin: 0; padding: 8px; border-radius: 4px; font-size: 12px; white-space: pre-wrap;"><code>{html.escape(snippet.secure_example)}</code></pre>
                </div>
                """

    cve_badges = "".join(
        f'<span class="cve-tag">{html.escape(c)}</span>'
        for c in (finding.get("matched_cve") or [])
    ) or '<span style="color: #64748b;">None</span>'

    return f"""
            <div class="finding-card severity-{sev} {'is-confirmed' if is_confirmed else ''}" data-severity="{sev}" data-confirmed="{str(is_confirmed).lower()}" data-lifecycle="{html.escape(lifecycle)}">
                <div class="finding-header" onclick="toggleDetails('{index}')">
                    <div class="finding-title">
                        <span class="method-tag method-{html.escape(finding['method'])}">{html.escape(finding['method'])}</span>
                        <span class="endpoint-name">{html.escape(finding['endpoint'])}</span>
                        {sev_badge}
                        {confirmed_badge}
                    </div>
                    <div class="finding-meta">
                        {confidence_badge}
                        <span class="status-code">HTTP {finding.get('status_code') or '---'}</span>
                        <span class="latency">{finding.get('response_time_ms') or 0} ms</span>
                        <span class="expand-icon" id="icon-{index}">▼</span>
                    </div>
                </div>
                <div class="finding-details" id="details-{index}" style="display: none;">
                    <div class="detail-grid">
                        <div class="detail-box">
                            <h4>Attack Details</h4>
                            <p><strong>Target App:</strong> <code>{html.escape(str(finding.get('target_app') or 'N/A'))}</code></p>
                            <p><strong>Attack Type:</strong> {html.escape(finding['attack_type'])}</p>
                            <p><strong>Lifecycle:</strong> <code>{html.escape(lifecycle)}</code> (Observations: {int(finding.get('observation_count') or 0)}, Errors: {int(finding.get('error_count') or 0)})</p>
                            <p><strong>Vulnerability Confidence:</strong> <code>{confidence_val:.2f}</code> ({confidence_pct}%)</p>
                            <p><strong>OWASP Category:</strong> {html.escape(owasp_cat)} - {html.escape(owasp_metadata.get(owasp_cat, {}).get('name', 'N/A'))}</p>
                            <p><strong>Matched CVEs:</strong> {cve_badges}</p>
                            <p><strong>Run ID:</strong> <code>{html.escape(str(finding.get('run_id') or 'N/A'))}</code></p>
                            <p><strong>Fingerprint:</strong> <code>{html.escape(finding.get('fingerprint', ''))}</code></p>
                        </div>
                        <div class="detail-box">
                            <h4>Evidence / Signal</h4>
                            <pre class="evidence-box">{html.escape(finding.get('evidence') or 'No signal detected')}</pre>
                        </div>
                    </div>

                    <div class="detail-box full-width">
                        <h4>Fuzzing Payload</h4>
                        <pre class="code-box"><code>{html.escape(payload_str)}</code></pre>
                    </div>

                    <div class="detail-box full-width" style="margin-top: 10px;">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                            <h4 style="margin: 0;">1-Click Reproduction (cURL)</h4>
                            <div style="display: flex; gap: 6px;">
                                <button onclick="navigator.clipboard.writeText(this.getAttribute('data-curl')); this.innerText='✓ Copied!';" data-curl="{html.escape(curl_bash)}" style="background: #38bdf8; color: #04101d; border: none; padding: 4px 10px; border-radius: 4px; font-weight: 600; cursor: pointer; font-size: 11px;">📋 Bash / PowerShell</button>
                                <button onclick="navigator.clipboard.writeText(this.getAttribute('data-curl')); this.innerText='✓ Copied!';" data-curl="{html.escape(curl_win_cmd)}" style="background: #0284c7; color: #ffffff; border: none; padding: 4px 10px; border-radius: 4px; font-weight: 600; cursor: pointer; font-size: 11px;">📋 Windows CMD</button>
                            </div>
                        </div>
                        <pre class="code-box" style="background: #020617; color: #38bdf8;"><code>{html.escape(curl_bash)}</code></pre>
                    </div>

                    <div class="remediation-box">
                        <strong>🛡️ Recommended Remediation:</strong>
                        <p>{html.escape(remediation)}</p>
                        {snippet_html}
                    </div>
                </div>
            </div>
            """


def render_html_document(
    findings: list[dict[str, Any]],
    metrics: dict[str, Any],
    *,
    target_name: str,
    target_url: str,
    now_str: str,
    owasp_metadata: dict[str, dict[str, str]],
    severity_colors: dict[str, tuple[str, str]],
    target_meta: dict[str, str] | None = None,
) -> str:
    """Render the full standalone HTML security report document."""
    findings_html = [
        render_finding_card(
            idx,
            f,
            target_url=target_url,
            owasp_metadata=owasp_metadata,
            severity_colors=severity_colors,
        )
        for idx, f in enumerate(findings, start=1)
    ]
    all_findings_str = (
        "\n".join(findings_html)
        if findings_html
        else "<div class='empty-state'>No security findings recorded. Target is clean!</div>"
    )

    owasp_bars = []
    max_owasp = max(metrics["owasp_counts"].values()) if metrics["owasp_counts"] else 1
    for cat, cnt in list(metrics["owasp_counts"].items())[:7]:
        pct = int((cnt / max_owasp) * 100)
        meta_name = owasp_metadata.get(cat, {}).get("name", cat)
        owasp_bars.append(f"""
            <div class="bar-row">
                <span class="bar-label">{html.escape(cat)} - {html.escape(meta_name)} ({cnt})</span>
                <div class="bar-container">
                    <div class="bar-fill" style="width: {pct}%;"></div>
                </div>
            </div>
            """)
    owasp_bars_html = "\n".join(owasp_bars) or "<p class='text-muted'>No OWASP categories detected.</p>"

    sev_counts = metrics["severity_counts"]
    total_sev = max(1, sum(sev_counts.values()))
    crit_pct = round((sev_counts["critical"] / total_sev) * 100)
    high_pct = round((sev_counts["high"] / total_sev) * 100)
    med_pct = round((sev_counts["medium"] / total_sev) * 100)
    low_pct = round((sev_counts["low"] / total_sev) * 100)

    meta = target_meta or {}
    target_apps = meta.get("apps") or target_name
    run_id_label = meta.get("run_id") or "N/A"
    schema_label = meta.get("schema") or "N/A"
    protocol_label = meta.get("protocol") or "API"

    return f"""<!DOCTYPE html>
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
        .badge-candidate {{ background: rgba(234, 179, 8, 0.16); color: var(--medium); border: 1px solid rgba(234, 179, 8, 0.4); }}
        .badge-inconclusive {{ background: rgba(56, 189, 248, 0.14); color: var(--accent); border: 1px solid rgba(56, 189, 248, 0.35); }}
        .badge-rejected {{ background: rgba(100, 116, 139, 0.15); color: var(--text-secondary); border: 1px solid rgba(100, 116, 139, 0.3); }}
        .badge-error {{ background: rgba(249, 115, 22, 0.18); color: var(--high); border: 1px solid rgba(249, 115, 22, 0.4); }}
        .badge-unconfirmed {{ background: rgba(100, 116, 139, 0.15); color: var(--text-secondary); }}
        .confidence-tag {{ font-size: 12px; color: #cbd5e1; background: rgba(30, 41, 59, 0.8); padding: 2px 8px; border-radius: 9999px; border: 1px solid var(--border); }}
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
        .target-banner {{
            background: linear-gradient(135deg, #111c2f 0%, #162238 100%);
            border: 1px solid var(--border);
            border-left: 4px solid var(--accent);
            border-radius: 10px;
            padding: 16px 20px;
            margin-bottom: 20px;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 12px 20px;
        }}
        .target-field-label {{ font-size: 11px; text-transform: uppercase; letter-spacing: 0.6px; color: var(--text-secondary); }}
        .target-field-value {{ font-size: 14px; font-weight: 600; color: #e2e8f0; margin-top: 2px; word-break: break-all; }}
        .target-field-value code {{ color: var(--accent); font-family: monospace; font-size: 13px; }}
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
                <p>Target: <strong>{html.escape(target_name)}</strong> | URL: <code>{html.escape(target_url)}</code> | Generated: {now_str}</p>
            </div>
            <div class="header-actions">
                <button onclick="window.print()">🖨️ Print / Save PDF</button>
            </div>
        </header>

        <section class="target-banner" aria-label="Target Metadata">
            <div>
                <div class="target-field-label">Target Name</div>
                <div class="target-field-value">{html.escape(target_name)}</div>
            </div>
            <div>
                <div class="target-field-label">Target Base URL</div>
                <div class="target-field-value"><code>{html.escape(target_url)}</code></div>
            </div>
            <div>
                <div class="target-field-label">Target App ID(s) & Protocol</div>
                <div class="target-field-value"><code>{html.escape(target_apps)}</code> ({html.escape(protocol_label)})</div>
            </div>
            <div>
                <div class="target-field-label">Latest Run ID / Schema</div>
                <div class="target-field-value"><code>{html.escape(run_id_label)}</code><br><span style="font-size: 12px; font-weight: 400; color: #94a3b8;">{html.escape(schema_label)}</span></div>
            </div>
        </section>

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
