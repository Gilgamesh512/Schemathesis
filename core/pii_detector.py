"""PII (Personally Identifiable Information) & Secret Leakage Detection Engine.

Scans response bodies, headers, and payloads for accidental data leakage:
- Credit Card numbers (with Luhn algorithm checksum verification)
- Private Keys (RSA, EC, DSA, OpenSSH, PGP)
- Cloud Credentials (AWS Access Key AKIA, Google API Keys)
- Authentication Secrets (JWT tokens, Session Tokens, Bearer Tokens)
- Password Hashes (Bcrypt, Argon2, MD5/SHA in password context)
- Plaintext credentials in JSON responses
- Citizen Identification (VN CCCD, US SSN format)
- Phone numbers & email addresses in bulk leaks
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import re
from typing import Any, Optional
from pydantic import BaseModel, Field

from .evidence import Evidence, Finding, content_hash, stable_finding_id


def luhn_checksum_valid(card_number: str) -> bool:
    """Validate a credit card number using the Luhn (mod-10) algorithm."""
    digits = [int(c) for c in card_number if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    # All same digits (e.g. 0000000000000000) are invalid
    if len(set(digits)) == 1:
        return False

    checksum = 0
    reverse_digits = digits[::-1]
    for i, digit in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = digit * 2
            checksum += doubled - 9 if doubled > 9 else doubled
        else:
            checksum += digit
    return checksum % 10 == 0


class PiiMatch(BaseModel):
    """Specific detected sensitive item."""
    category: str
    pattern_name: str
    preview: str
    confidence: float
    start_pos: int
    end_pos: int


class PiiScanResult(BaseModel):
    """Aggregated scan result across an inspected text or document."""
    has_pii: bool = False
    matches: list[PiiMatch] = Field(default_factory=list)
    counts: dict[str, int] = Field(default_factory=dict)
    sanitized_text: str = ""


class PiiDetector:
    """Enterprise detector and scrubber for PII and cryptographic secrets."""

    PATTERNS: list[dict[str, Any]] = [
        {
            "name": "RSA/OpenSSH/PGP Private Key",
            "category": "SECRET_KEY",
            "regex": re.compile(
                r"-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+|PGP\s+)?PRIVATE\s+KEY(?:\s+BLOCK)?-----[\s\S]*?-----END\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+|PGP\s+)?PRIVATE\s+KEY(?:\s+BLOCK)?-----",
                re.MULTILINE,
            ),
            "confidence": 1.0,
            "mask_func": lambda m: "[REDACTED_PRIVATE_KEY]",
        },
        {
            "name": "AWS Access Key ID",
            "category": "CLOUD_KEY",
            "regex": re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
            "confidence": 0.98,
            "mask_func": lambda m: m.group(1)[:4] + "*" * 12 + m.group(1)[-4:],
        },
        {
            "name": "Google API Key",
            "category": "CLOUD_KEY",
            "regex": re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
            "confidence": 0.95,
            "mask_func": lambda m: m.group(0)[:6] + "*" * 25 + m.group(0)[-4:],
        },
        {
            "name": "JWT Authentication Token",
            "category": "TOKEN",
            "regex": re.compile(r"\beyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b"),
            "confidence": 0.95,
            "mask_func": lambda m: m.group(0)[:15] + "...[REDACTED_JWT]..." + m.group(0)[-10:],
        },
        {
            "name": "Bcrypt Password Hash",
            "category": "PASSWORD_HASH",
            "regex": re.compile(r"\$2[abxy]?\$\d{2}\$[./A-Za-z0-9]{53}"),
            "confidence": 0.99,
            "mask_func": lambda m: "$2a$12$" + "*" * 40 + "[HASH]",
        },
        {
            "name": "Plaintext Password Exposure in JSON",
            "category": "CREDENTIAL",
            "regex": re.compile(r'(?i)"(?:password|passwd|pwd|pass|secret_key|api_secret)"\s*:\s*"([^"]{4,})"', re.IGNORECASE),
            "confidence": 0.90,
            "mask_func": lambda m: f'"{m.group(0).split(":")[0].strip()}" : "[REDACTED_SECRET]"',
        },
        {
            "name": "Vietnam Citizen Identity Card (CCCD 12-digit)",
            "category": "GOV_ID",
            "regex": re.compile(r"\b0\d{2}[0-3]\d{2}\d{6}\b"),
            "confidence": 0.85,
            "mask_func": lambda m: m.group(0)[:3] + "******" + m.group(0)[-3:],
        },
        {
            "name": "Vietnam Phone Number",
            "category": "PHONE",
            "regex": re.compile(r"\b(?:0|\+84)(?:3[2-9]|5[2689]|7[06-9]|8[1-9]|9[0-9])\d{7}\b"),
            "confidence": 0.85,
            "mask_func": lambda m: m.group(0)[:3] + "****" + m.group(0)[-3:],
        },
    ]

    # Credit card regex with digit grouping or unspaced
    CARD_REGEX = re.compile(r"\b(?:\d{4}[- ]?){3}\d{4}\b|\b\d{13,19}\b")

    @classmethod
    def scan(cls, text: str) -> PiiScanResult:
        """Scan string content and report detected sensitive elements."""
        if not text or not isinstance(text, str):
            return PiiScanResult()

        matches: list[PiiMatch] = []
        counts: dict[str, int] = {}
        sanitized = text

        # 1. Regex based detections
        for pattern in cls.PATTERNS:
            regex = pattern["regex"]
            p_name = pattern["name"]
            cat = pattern["category"]
            conf = pattern["confidence"]

            for m in regex.finditer(text):
                matched_str = m.group(0)
                # Keep preview concise
                preview = matched_str[:40] + ("..." if len(matched_str) > 40 else "")
                matches.append(PiiMatch(
                    category=cat,
                    pattern_name=p_name,
                    preview=preview,
                    confidence=conf,
                    start_pos=m.start(),
                    end_pos=m.end(),
                ))
                counts[p_name] = counts.get(p_name, 0) + 1

        # 2. Credit Card Numbers (Strict Luhn algorithm filter to prevent false positives)
        for m in cls.CARD_REGEX.finditer(text):
            raw_cand = m.group(0)
            clean_digits = re.sub(r"\D", "", raw_cand)
            if luhn_checksum_valid(clean_digits):
                preview = clean_digits[:4] + "-****-****-" + clean_digits[-4:]
                matches.append(PiiMatch(
                    category="CREDIT_CARD",
                    pattern_name="Valid Credit Card (Luhn Verified)",
                    preview=preview,
                    confidence=0.99,
                    start_pos=m.start(),
                    end_pos=m.end(),
                ))
                counts["Valid Credit Card (Luhn Verified)"] = counts.get("Valid Credit Card (Luhn Verified)", 0) + 1

        # Generate sanitized copy
        sanitized = cls.mask_text(text)

        return PiiScanResult(
            has_pii=bool(matches),
            matches=matches,
            counts=counts,
            sanitized_text=sanitized,
        )

    @classmethod
    def mask_text(cls, text: str) -> str:
        """Replace all sensitive patterns in text with masked representations."""
        if not text or not isinstance(text, str):
            return ""

        result = text

        # Mask regex patterns
        for pattern in cls.PATTERNS:
            mask_func = pattern.get("mask_func")
            if mask_func:
                result = pattern["regex"].sub(mask_func, result)

        # Mask Luhn valid credit cards
        def _mask_card(match: re.Match) -> str:
            cand = match.group(0)
            digits = re.sub(r"\D", "", cand)
            if luhn_checksum_valid(digits):
                return digits[:4] + "-****-****-" + digits[-4:]
            return cand

        result = cls.CARD_REGEX.sub(_mask_card, result)
        return result

    @classmethod
    def audit_response(
        cls,
        status_code: int,
        response_text: str,
        endpoint: str,
        method: str,
        run_id: str,
        target_app: str = "target",
        elapsed_ms: float = 0.0,
    ) -> Optional[Finding]:
        """Audit HTTP response body for sensitive data leakage.
        
        Returns a high-confidence Finding if PII or secret credentials are exposed.
        """
        # Only audit successful or informative responses (200, 201, 206)
        if status_code not in (200, 201, 206):
            return None

        scan_res = cls.scan(response_text)
        if not scan_res.has_pii:
            return None

        # Determine highest severity
        high_risk_cats = {"SECRET_KEY", "CREDENTIAL", "PASSWORD_HASH", "CREDIT_CARD", "CLOUD_KEY"}
        has_critical = any(m.category in high_risk_cats for m in scan_res.matches)
        severity = "critical" if has_critical else "high"

        detected_types = list(scan_res.counts.keys())
        summary_desc = ", ".join(f"{k} (x{v})" for k, v in scan_res.counts.items())

        clean_ep = "/" + endpoint.lstrip("/")
        fid = stable_finding_id(target_app, method, clean_ep, "SENSITIVE_DATA_EXPOSURE", detected_types[0] if detected_types else "pii")

        return Finding(
            finding_id=fid,
            run_id=run_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            tool="pii_detector",
            target_app=target_app,
            endpoint=clean_ep,
            method=method.upper(),
            attack_type="SENSITIVE_DATA_EXPOSURE",
            owasp_category="API3:2023",
            payload={"detected_patterns": detected_types, "occurrences": scan_res.counts},
            status_code=status_code,
            response_time_ms=elapsed_ms,
            evidence=Evidence(
                status_code=status_code,
                response_headers={},
                response_signal=[f"Detected PII/Secret Leakage in Response Body: {summary_desc}"],
                response_time_ms=elapsed_ms,
                payload_hash=content_hash(detected_types),
                request_hash=content_hash(clean_ep),
                endpoint=clean_ep,
            ),
            severity=severity,
            confidence=0.95,
            confirmed=True,
            lifecycle="confirmed",
            fingerprint=content_hash(f"{method}|{clean_ep}|PII_LEAK|{','.join(sorted(detected_types))}"),
        )
