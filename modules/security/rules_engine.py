#!/usr/bin/env python3
"""
rules_engine.py
Security Rules & CVE Enrichment Engine.

- OWASP API Security Top 10 (2023): Category mapping, heuristic matching, and remediation advice.
- CVE API 2.0 Integration: Queries NVD NIST CVE API 2.0 with automatic fallback to Google OSV API (api.osv.dev).
- CVSS v3.1 Scoring & Severity Evaluation.

Usage:
    python3 -m modules.security.rules_engine --update
    python3 -m modules.security.rules_engine --update --days 90 --api-key <NVD_KEY>
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import requests

from core import ProjectPaths

PROJECT_PATHS = ProjectPaths.from_root(PROJECT_ROOT)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OSV_API_URL = "https://api.osv.dev/v1/query"

# Keywords related to target API stacks (REST, GraphQL, Flask, Express, JWT)
DEFAULT_KEYWORDS = [
    "REST API injection",
    "JWT authentication bypass",
    "GraphQL injection",
    "SQL injection API",
    "SSRF",
    "mass assignment",
    "broken object level authorization",
]

# Common API stack packages used for OSV fallback when NVD is rate-limited
DEFAULT_OSV_PACKAGES = [
    ("flask", "PyPI"),
    ("graphene", "PyPI"),
    ("express", "npm"),
    ("jsonwebtoken", "npm"),
    ("spring-boot", "Maven"),
]

RATE_LIMIT_SLEEP_S = 6  # Safe pacing without NVD API key (~5 req/30s)
NVD_PAGE_SIZE = 50


def _severity_from_cvss(score: Optional[float]) -> str:
    if score is None:
        return "unknown"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def fetch_cves_for_keyword(keyword: str, days_back: int, api_key: Optional[str]) -> list[dict]:
    """Query NVD CVE API 2.0 and return concise CVE entries (id, desc, cvss, severity)."""
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days_back)
    params = {
        "keywordSearch": keyword,
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": NVD_PAGE_SIZE,
    }
    headers = {"apiKey": api_key} if api_key else {}

    out = []
    start_index = 0
    total_results = None
    while total_results is None or start_index < total_results:
        params["startIndex"] = start_index
        try:
            resp = requests.get(NVD_API_URL, params=params, headers=headers, timeout=20)
            resp.raise_for_status()
            data = resp.json()
        except (requests.RequestException, ValueError) as exc:
            print(f"[WARNING] Failed to query NVD API for keyword '{keyword}' "
                  f"(startIndex={start_index}): {exc}", file=sys.stderr)
            break

        total_results = int(data.get("totalResults", 0))
        page = data.get("vulnerabilities", [])
        print(f"[INFO] NVD '{keyword}': {start_index + len(page)}/{total_results}")
        for item in page:
            cve = item.get("cve", {})
            cve_id = cve.get("id")
            descs = cve.get("descriptions", [])
            desc_en = next((d["value"] for d in descs if d.get("lang") == "en"), "")

            metrics = cve.get("metrics", {})
            score = None
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics and metrics[key]:
                    score = metrics[key][0]["cvssData"].get("baseScore")
                    break

            cpe_uris = []
            for node in cve.get("configurations", []):
                for cpe_match in node.get("nodes", []):
                    for match in cpe_match.get("cpeMatch", []):
                        if match.get("criteria"):
                            cpe_uris.append(match["criteria"])

            out.append({
                "cve_id": cve_id,
                "keyword": keyword,
                "description": desc_en[:300],
                "cvss_score": score,
                "severity": _severity_from_cvss(score),
                "published": cve.get("published"),
                "cpe_uris": sorted(set(cpe_uris)),
            })
        if not page:
            break
        start_index += len(page)
    return out


def fetch_cves_from_osv(package_name: str, ecosystem: str = "PyPI") -> list[dict]:
    """Fallback query to Google OSV API (Open Source Vulnerabilities) - fast, open, zero rate-limit."""
    try:
        resp = requests.post(
            OSV_API_URL,
            json={"package": {"name": package_name, "ecosystem": ecosystem}},
            timeout=10,
        )
        if resp.status_code != 200:
            return []
        data = resp.json()
        vulns = data.get("vulns", [])
        out = []
        for v in vulns[:10]:
            vid = v.get("id")
            # Prefer CVE alias if available
            aliases = v.get("aliases", [])
            cve_alias = next((a for a in aliases if a.startswith("CVE-")), vid)
            desc = v.get("summary") or v.get("details", "")
            out.append({
                "cve_id": cve_alias,
                "keyword": f"{package_name} ({ecosystem})",
                "description": desc[:300],
                "cvss_score": 7.5,
                "severity": "high",
                "published": v.get("published"),
                "cpe_uris": [f"cpe:2.3:a:{package_name}:{package_name}:*:*:*:*:*:*:*:*"],
            })
        return out
    except Exception as exc:
        print(f"[WARNING] Failed to query OSV API for {package_name}: {exc}", file=sys.stderr)
        return []


def update_from_nvd(rules: dict, keywords: list[str], days_back: int,
                     api_key: Optional[str] = None) -> dict:
    all_cves = []
    nvd_failed = False
    for kw in keywords:
        print(f"[INFO] Querying NVD: '{kw}' (last {days_back} days)...")
        fetched = fetch_cves_for_keyword(kw, days_back, api_key)
        all_cves.extend(fetched)
        if not fetched:
            nvd_failed = True
        if not api_key:
            time.sleep(RATE_LIMIT_SLEEP_S)

    # Fallback to Google OSV API if NVD returns empty or fails due to rate limits/network blocks
    if not all_cves or nvd_failed:
        print("[INFO] Activating fallback to Google OSV API (api.osv.dev) for API stack packages...")
        for pkg, eco in DEFAULT_OSV_PACKAGES:
            osv_results = fetch_cves_from_osv(pkg, eco)
            all_cves.extend(osv_results)

    # Deduplicate by cve_id, retaining highest CVSS score
    by_id: dict[str, dict] = {}
    for c in all_cves:
        cid = c["cve_id"]
        if cid is None:
            continue
        if cid not in by_id or (c["cvss_score"] or 0) > (by_id[cid]["cvss_score"] or 0):
            by_id[cid] = c

    rules["cve_signals"] = sorted(by_id.values(),
                                   key=lambda c: c["cvss_score"] or 0, reverse=True)
    rules["meta"]["cve_last_updated"] = datetime.now(timezone.utc).isoformat()
    print(f"[DONE] Updated {len(rules['cve_signals'])} relevant CVEs.")
    return rules


def load_rules(path: str) -> dict:
    p = Path(path)
    if not p.exists():
        print(f"[ERROR] Rules file not found at {path}. Run --update to generate it "
              "or provide the bundled rules.json.", file=sys.stderr)
        sys.exit(1)
    return json.loads(p.read_text())


def save_rules(rules: dict, path: str) -> None:
    Path(path).write_text(json.dumps(rules, indent=2, ensure_ascii=False))


def get_all_signals(rules: dict) -> list[str]:
    """Return all static and category error signals for response evaluation."""
    signals = list(rules.get("static_error_signals", []))
    for cat in rules.get("owasp_categories", {}).values():
        signals.extend(cat.get("signals", []))
    return sorted(set(s.lower() for s in signals))


STOPWORDS = {"api", "the", "and", "for", "with", "via", "attackers", "allows"}

# Synonym map bridging attack_type labels to natural-language CVE descriptions
ATTACK_TYPE_SYNONYMS = {
    "sqli": ["sql", "sql injection", "injection"],
    "xss": ["cross-site scripting", "script injection", "xss"],
    "ssrf": ["server-side request forgery", "ssrf"],
    "bola": ["object level authorization", "idor", "authorization bypass"],
    "bfla": ["function level authorization", "authorization bypass", "privilege"],
    "massassignment": ["mass assignment", "property level authorization"],
    "jwt": ["jwt", "json web token", "authentication bypass"],
    "xxe": ["xml external entity", "xxe"],
    "deserialization": ["deserialization", "insecure deserialization"],
    "pathtraversal": ["path traversal", "directory traversal", "local file inclusion", "lfi"],
    "ssti": ["template injection", "server-side template injection", "ssti"],
    "nosqlinjection": ["nosql injection", "nosql", "mongodb injection"],
    "timebasedsqli": ["sql", "sql injection", "blind sql", "sleep"],
}


def match_cves_by_keyword(rules: dict, attack_type: str, owasp_category: Optional[str] = None,
                          technology: Optional[dict] = None
                           ) -> list[dict]:
    """Match cached CVEs relevant to the tested attack_type using the synonym table."""
    key = attack_type.lower().replace(" ", "").replace("_", "")
    phrases = list(ATTACK_TYPE_SYNONYMS.get(key, [attack_type.lower()]))

    if owasp_category and rules.get("owasp_categories", {}).get(owasp_category):
        name = rules["owasp_categories"][owasp_category]["name"].lower()
        phrases.extend(w for w in name.replace("(", "").replace(")", "").split()
                        if len(w) >= 4 and w not in STOPWORDS)

    technology_terms = []
    if technology:
        technology_terms = [str(value).lower() for value in technology.values() if value]

    matched = []
    for cve in rules.get("cve_signals", []):
        desc_l = cve["description"].lower()
        attack_match = any(p in desc_l for p in phrases)
        cpe_text = " ".join(cve.get("cpe_uris", [])).lower()
        cpe_match = not technology_terms or bool(cpe_text) and any(
            term in cpe_text for term in technology_terms
        )
        if attack_match and cpe_match:
            matched.append(cve)
    return matched[:3]


def main():
    ap = argparse.ArgumentParser(description="Update OWASP/CVE security rules from NVD and Google OSV")
    ap.add_argument("--rules", default=str(PROJECT_PATHS.config / "rules.json"))
    ap.add_argument("--update", action="store_true", help="Query NVD/OSV APIs to refresh CVEs")
    ap.add_argument("--days", type=int, default=30)
    ap.add_argument("--api-key", default=None, help="NVD API key (recommended for higher rate limits)")
    ap.add_argument("--keywords", nargs="*", default=None, help="Override default search keywords")
    args = ap.parse_args()

    rules_path = PROJECT_PATHS.resolve(args.rules, allow_outside=True)
    if not rules_path.exists():
        print(f"[ERROR] {rules_path} does not exist. Create or restore the base rules.json first.",
              file=sys.stderr)
        sys.exit(1)

    rules = load_rules(str(rules_path))

    if args.update:
        keywords = args.keywords or DEFAULT_KEYWORDS
        rules = update_from_nvd(rules, keywords, args.days, args.api_key)
        save_rules(rules, str(rules_path))
    else:
        print(f"[INFO] Current rules: {len(get_all_signals(rules))} signals, "
              f"{len(rules.get('cve_signals', []))} cached CVEs "
              f"(last updated: {rules['meta'].get('cve_last_updated')}).")


if __name__ == "__main__":
    main()
