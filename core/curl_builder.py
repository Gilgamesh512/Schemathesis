"""core/curl_builder.py — Cross-platform cURL command generator (1-click reproduce).

Converts any security finding into a reproducible cURL command for Linux, macOS,
PowerShell, and Windows CMD.
"""

from __future__ import annotations

import json
import urllib.parse
from typing import Any


def build_curl_command(
    method: str,
    url: str,
    *,
    headers: dict[str, Any] | None = None,
    params: dict[str, Any] | None = None,
    data: Any = None,
    json_data: Any = None,
    cookies: dict[str, str] | None = None,
    insecure: bool = False,
    shell: str = "bash",
) -> str:
    """Build a cross-platform cURL command string.

    - shell='bash': Compatible with Linux, macOS, WSL, and PowerShell (single-quoted payload).
    - shell='cmd': Compatible with Windows cmd.exe (escaped double-quoted payload).
    """
    clean_method = method.upper().strip()
    target_url = url.strip()

    # Append query parameters if supplied
    if params:
        encoded_params = urllib.parse.urlencode(params)
        sep = "&" if "?" in target_url else "?"
        target_url = f"{target_url}{sep}{encoded_params}"

    cmd_parts: list[str] = ["curl", "-i", "-s"]

    if insecure:
        cmd_parts.append("-k")

    cmd_parts.extend(["-X", clean_method])
    cmd_parts.append(f'"{target_url}"')

    req_headers = dict(headers or {})

    if cookies:
        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
        req_headers["Cookie"] = cookie_str

    for h_name, h_val in req_headers.items():
        if h_name.lower() in ("content-length", "host"):
            continue
        clean_val = str(h_val).replace('"', '\\"')
        cmd_parts.extend(["-H", f'"{h_name}: {clean_val}"'])

    body_payload = None
    if json_data is not None:
        if isinstance(json_data, (dict, list)):
            body_payload = json.dumps(json_data, ensure_ascii=False)
        else:
            body_payload = str(json_data)
        if "Content-Type" not in req_headers and "content-type" not in req_headers:
            cmd_parts.extend(["-H", '"Content-Type: application/json"'])
    elif data is not None:
        if isinstance(data, dict):
            body_payload = urllib.parse.urlencode(data)
            if "Content-Type" not in req_headers and "content-type" not in req_headers:
                cmd_parts.extend(["-H", '"Content-Type: application/x-www-form-urlencoded"'])
        else:
            body_payload = str(data)

    if body_payload is not None:
        is_cmd = shell.lower() in ("cmd", "cmd.exe", "windows")
        if is_cmd:
            escaped_body = body_payload.replace('"', '\\"')
            cmd_parts.extend(["-d", f'"{escaped_body}"'])
        else:
            escaped_body = body_payload.replace("'", "'\\''")
            cmd_parts.extend(["-d", f"'{escaped_body}'"])

    return " ".join(cmd_parts)


def build_curl_dual(
    method: str,
    url: str,
    *,
    headers: dict[str, Any] | None = None,
    params: dict[str, Any] | None = None,
    data: Any = None,
    json_data: Any = None,
    cookies: dict[str, str] | None = None,
    insecure: bool = False,
) -> dict[str, str]:
    """Generate both 'bash' (POSIX/PowerShell) and 'cmd' (Windows cmd.exe) cURL variants."""
    return {
        "bash": build_curl_command(
            method, url, headers=headers, params=params, data=data,
            json_data=json_data, cookies=cookies, insecure=insecure, shell="bash"
        ),
        "cmd": build_curl_command(
            method, url, headers=headers, params=params, data=data,
            json_data=json_data, cookies=cookies, insecure=insecure, shell="cmd"
        ),
    }


def build_curl_from_finding(finding: Any, base_url: str = "", shell: str = "bash") -> str:
    """Build a cURL command from a Finding model instance or finding dictionary."""
    if isinstance(finding, dict):
        endpoint = finding.get("endpoint") or "/"
        method = finding.get("method") or "GET"
        payload = finding.get("payload")
        evidence = finding.get("evidence")
    else:
        endpoint = getattr(finding, "endpoint", "") or "/"
        method = getattr(finding, "method", "GET") or "GET"
        payload = getattr(finding, "payload", None)
        evidence = getattr(finding, "evidence", None)

    # Assemble full target URL
    if endpoint.startswith("http://") or endpoint.startswith("https://"):
        full_url = endpoint
    else:
        full_url = f"{base_url.rstrip('/')}/{endpoint.lstrip('/')}" if base_url else endpoint

    # Extract auth context or non-redacted headers from evidence
    headers: dict[str, Any] = {}
    if evidence:
        if isinstance(evidence, dict):
            auth_ctx = evidence.get("auth_context") or {}
        else:
            auth_ctx = getattr(evidence, "auth_context", {}) or {}
        if isinstance(auth_ctx, dict):
            if "header" in auth_ctx and "token" in auth_ctx:
                headers[auth_ctx["header"]] = auth_ctx["token"]
            for k, v in auth_ctx.items():
                if k not in ("header", "token") and not k.endswith("_hash") and isinstance(v, (str, int)):
                    if str(v) != "<REDACTED>":
                        headers[k] = str(v)

    json_data = None
    data = None
    if payload is not None:
        if isinstance(payload, (dict, list)):
            json_data = payload
        else:
            data = payload

    return build_curl_command(
        method=method,
        url=full_url,
        headers=headers if headers else None,
        json_data=json_data,
        data=data,
        shell=shell,
    )


def build_curl_dual_from_finding(finding: Any, base_url: str = "") -> dict[str, str]:
    """Generate both Bash/PowerShell and Windows CMD cURL commands from a finding."""
    return {
        "bash": build_curl_from_finding(finding, base_url=base_url, shell="bash"),
        "cmd": build_curl_from_finding(finding, base_url=base_url, shell="cmd"),
    }
