"""Enterprise Alerting and Webhook Notification Module.

Supports sending DevSecOps Quality Gate and Security Fuzzing alerts
to Slack, Microsoft Teams, Discord, and Generic JSON Webhooks.
"""

from __future__ import annotations

import json
from typing import Any, Optional
import urllib.error
import urllib.request


def send_webhook_alert(
    webhook_url: str,
    title: str,
    summary: str,
    status: str = "FAILED",
    metrics: Optional[dict[str, Any]] = None,
    timeout: float = 8.0,
) -> bool:
    """Send an alert notification to a webhook endpoint.

    Auto-detects payload format for Slack, Discord, Microsoft Teams, or Generic Webhook.
    """
    if not webhook_url or not webhook_url.startswith(("http://", "https://")):
        return False

    metrics = metrics or {}
    is_failed = status.upper() in ("FAILED", "BLOCKED", "ERROR")
    color = "#ef4444" if is_failed else "#10b981"  # Red or Green
    emoji = "🚨" if is_failed else "✅"

    # Construct format-specific payload
    payload: dict[str, Any]

    if "hooks.slack.com" in webhook_url:
        fields = [
            {"title": "Quality Gate Status", "value": f"{emoji} {status.upper()}", "short": True},
            {"title": "Target", "value": str(metrics.get("target", "N/A")), "short": True},
            {"title": "Critical Issues", "value": str(metrics.get("critical", 0)), "short": True},
            {"title": "High Issues", "value": str(metrics.get("high", 0)), "short": True},
            {"title": "Confirmed Exploits", "value": str(metrics.get("confirmed", 0)), "short": True},
            {"title": "Total Findings", "value": str(metrics.get("total", 0)), "short": True},
        ]
        payload = {
            "text": f"{emoji} *{title}*",
            "attachments": [{
                "color": color,
                "text": summary,
                "fields": fields,
            }],
        }
    elif "discord.com" in webhook_url or "discordapp.com" in webhook_url:
        payload = {
            "content": f"{emoji} **{title}**",
            "embeds": [{
                "title": f"DevSecOps Gate: {status.upper()}",
                "description": summary,
                "color": 0xEF4444 if is_failed else 0x10B981,
                "fields": [
                    {"name": k.capitalize(), "value": str(v), "inline": True}
                    for k, v in metrics.items()
                ],
            }],
        }
    elif "office.com" in webhook_url or "webhook.office" in webhook_url:
        # Microsoft Teams Connector / Power Automate format
        facts = [{"name": k.capitalize(), "value": str(v)} for k, v in metrics.items()]
        payload = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": "EF4444" if is_failed else "10B981",
            "summary": title,
            "sections": [{
                "activityTitle": f"{emoji} {title}",
                "activitySubtitle": summary,
                "facts": facts,
                "markdown": True,
            }],
        }
    else:
        # Generic DevSecOps JSON Webhook
        payload = {
            "event": "security_quality_gate",
            "title": title,
            "status": status.upper(),
            "summary": summary,
            "metrics": metrics,
        }

    try:
        data_bytes = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            webhook_url,
            data=data_bytes,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "Schemathesis-Enterprise-Alerter/2.0",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status in (200, 201, 202, 204)
    except Exception:
        return False


__all__ = ["send_webhook_alert"]
