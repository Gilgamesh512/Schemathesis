"""OASIS SARIF v2.1.0 exporter for DevSecOps & CI/CD integration."""

from __future__ import annotations

import json
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .remediation_engine import RemediationEngine
from .validation_policy import sanitize_confidence


def build_sarif_document(
    findings: list[dict[str, Any]],
    *,
    owasp_metadata: dict[str, dict[str, str]],
    project_root: Path,
    sign_fn: Callable[[str], str],
    target_info: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a signed OASIS SARIF v2.1.0 report document from normalized findings."""
    schema_file_ref = ""
    if target_info:
        raw_spec = (
            target_info.get("schema")
            or target_info.get("schema_file")
            or target_info.get("schema_path")
            or ""
        )
        if raw_spec and not str(raw_spec).startswith(("http://", "https://")):
            try:
                rel_p = Path(raw_spec).resolve()
                if project_root in rel_p.parents or rel_p == project_root:
                    schema_file_ref = rel_p.relative_to(project_root).as_posix()
                else:
                    schema_file_ref = Path(raw_spec).as_posix()
            except Exception:
                schema_file_ref = str(raw_spec)

    rules_map: dict[str, dict[str, Any]] = {}
    sarif_results: list[dict[str, Any]] = []
    owasp_keys = list(owasp_metadata.keys())

    for f in findings:
        rule_id = f.get("owasp_category") or "API-SECURITY"
        if rule_id not in rules_map:
            meta = owasp_metadata.get(rule_id, {})
            help_text = meta.get(
                "remediation",
                "Apply strict authorization, input validation, and access controls.",
            )
            sarif_snippet = RemediationEngine.get_snippet(rule_id)
            help_md = help_text
            if sarif_snippet:
                help_md += (
                    f"\n\n### Recommended Fix ({sarif_snippet.framework})\n\n"
                    f"```\n{sarif_snippet.secure_example}\n```"
                )

            rule_entry: dict[str, Any] = {
                "id": rule_id,
                "name": meta.get("name", rule_id),
                "shortDescription": {"text": meta.get("name", rule_id)},
                "fullDescription": {"text": f"OWASP API Security Top 10 category {rule_id}"},
                "help": {
                    "text": help_text,
                    "markdown": help_md,
                },
                "defaultConfiguration": {
                    "level": "error" if f.get("severity") in ("critical", "high") else "warning"
                },
            }
            if rule_id in owasp_keys:
                rule_entry["relationships"] = [{
                    "target": {
                        "id": rule_id,
                        "index": owasp_keys.index(rule_id),
                        "toolComponent": {"name": "OWASP API Security Top 10 2023"},
                    },
                    "kinds": ["superset"],
                }]
            rules_map[rule_id] = rule_entry

        sev = f.get("severity", "info")
        level = "error" if sev in ("critical", "high") else ("warning" if sev == "medium" else "note")
        msg_text = (
            f"[{f.get('method', 'GET')}] {f.get('endpoint', '/')} - "
            f"{f.get('attack_type', 'Vulnerability')} ({sev.upper()}). "
            f"Confirmed: {f.get('confirmed', False)}. {f.get('evidence', '')}"
        )

        if schema_file_ref:
            artifact_uri = schema_file_ref
        else:
            endpoint_raw = str(f.get("endpoint", "/"))
            artifact_uri = urllib.parse.quote(endpoint_raw, safe="/:@?&=#%+")

        lifecycle_val = str(
            f.get("lifecycle") or f.get("outcome") or ("confirmed" if f.get("confirmed") else "unknown")
        ).strip().lower()
        confidence_val, _ = sanitize_confidence(f.get("confidence"), default=0.0)

        finding_props: dict[str, Any] = {
            "finding_id": f.get("finding_id", ""),
            "target_app": f.get("target_app", ""),
            "confirmed": bool(f.get("confirmed", False)),
            "lifecycle": lifecycle_val,
            "outcome": lifecycle_val,
            "confidence": confidence_val,
            "observation_count": int(f.get("observation_count") or 0),
            "error_count": int(f.get("error_count") or 0),
            "severity": sev,
            "owasp_category": rule_id,
            "attack_type": f.get("attack_type", ""),
            "matched_cve": f.get("matched_cve", []),
            "cwe_id": f.get("cwe_id") or "CWE-20",
        }
        if f.get("curl_command"):
            finding_props["curl_command"] = f.get("curl_command")

        res_entry: dict[str, Any] = {
            "ruleId": rule_id,
            "level": level,
            "message": {"text": msg_text},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": artifact_uri,
                        "uriBaseId": "%SRCROOT%" if schema_file_ref else None,
                    },
                    "region": {"startLine": int(f.get("line_number") or 1)},
                }
            }],
            "properties": finding_props,
        }
        if rule_id in owasp_keys:
            res_entry["taxa"] = [{
                "id": rule_id,
                "index": owasp_keys.index(rule_id),
                "toolComponent": {"name": "OWASP API Security Top 10 2023"},
            }]
        sarif_results.append(res_entry)

    taxonomies = [{
        "name": "OWASP API Security Top 10 2023",
        "version": "2023",
        "organization": "OWASP",
        "shortDescription": {"text": "OWASP API Security Top 10 Standard (2023)"},
        "taxa": [
            {
                "id": cid,
                "name": c_meta.get("name", cid),
                "shortDescription": {"text": c_meta.get("name", cid)},
                "helpUri": (
                    f"https://owasp.org/API-Security/editions/2023/en/"
                    f"0xa{idx + 1}-{cid.lower().replace(':', '-')}/"
                ),
            }
            for idx, (cid, c_meta) in enumerate(owasp_metadata.items())
        ],
    }]

    sarif_doc: dict[str, Any] = {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Schemathesis API Security Fuzzer",
                    "informationUri": "https://github.com/Gilgamesh512/Schemathesis",
                    "version": "2.0.0",
                    "rules": list(rules_map.values()),
                    "supportedTaxonomies": [{"name": "OWASP API Security Top 10 2023"}],
                }
            },
            "taxonomies": taxonomies,
            "results": sarif_results,
        }],
    }

    raw_sarif_str = json.dumps(sarif_doc, indent=2, ensure_ascii=False)
    sarif_sig = sign_fn(raw_sarif_str)
    sarif_doc["runs"][0]["properties"] = {
        "tamper_evident_hmac": sarif_sig,
        "signature_algorithm": "HMAC-SHA256",
        "signed_at": datetime.now(timezone.utc).isoformat(),
    }
    return sarif_doc
