"""Schema-Conforming Semantic Mutation Engine.

Generates security mutation probes that strictly adhere to target schema constraints
(types, formats, boundaries, enums, regex patterns), bypassing frontend/framework
validation barriers (FastAPI, NestJS, Spring Boot, Pydantic) to reach deep business
logic and database layers without being rejected at HTTP 400/422.
"""

from __future__ import annotations

import re
import uuid
from typing import Any, Optional
from pydantic import BaseModel, Field


class ParamSchema(BaseModel):
    """Normalized parameter or body property schema descriptor."""
    name: str
    location: str = "query"  # "query" | "path" | "body" | "header"
    type: str = "string"     # "string" | "integer" | "number" | "boolean" | "array" | "object"
    format: Optional[str] = None  # "uuid", "email", "date-time", "date", "uri", "int32", "int64"...
    enum: list[Any] = Field(default_factory=list)
    pattern: Optional[str] = None
    minimum: Optional[float] = None
    maximum: Optional[float] = None
    required: bool = False
    default: Optional[Any] = None
    properties: dict[str, Any] = Field(default_factory=dict)


class SemanticProbe(BaseModel):
    """Targeted security mutation probe with schema conformance."""
    attack_type: str
    payload_value: Any
    owasp_category: str
    expected_signal: list[str] = Field(default_factory=list)
    description: str = ""
    conformance_mode: str = "schema_conformant"  # "schema_conformant" | "boundary_violation"


class SemanticMutationEngine:
    """Produces intelligent, schema-aware security probes tailored to field specifications."""

    @classmethod
    def inspect_param(cls, name: str, location: str, raw_definition: Any) -> ParamSchema:
        """Extract normalized schema descriptor from an OpenAPI parameter definition."""
        schema_dict: dict[str, Any] = {}
        required = False

        if isinstance(raw_definition, dict):
            required = raw_definition.get("required", False)
            schema_dict = raw_definition.get("schema", raw_definition)
        elif hasattr(raw_definition, "definition"):
            def_dict = getattr(raw_definition, "definition", {})
            if isinstance(def_dict, dict):
                required = def_dict.get("required", False)
                schema_dict = def_dict.get("schema", def_dict)

        param_type = str(schema_dict.get("type", "string")).lower()
        param_format = schema_dict.get("format")
        if param_format:
            param_format = str(param_format).lower()

        # Heuristic detection if type is string but name suggests specific format
        lower_name = name.lower()
        if param_type == "string" and not param_format:
            if any(k in lower_name for k in ("uuid", "guid")) or lower_name.endswith("_id"):
                param_format = "uuid"
            elif "email" in lower_name or "mail" in lower_name:
                param_format = "email"
            elif any(k in lower_name for k in ("url", "uri", "callback", "redirect", "webhook")):
                param_format = "uri"
            elif any(k in lower_name for k in ("timestamp", "created_at", "updated_at", "datetime", "date_time")):
                param_format = "date-time"
            elif "date" in lower_name:
                param_format = "date"

        enum_vals = schema_dict.get("enum", [])
        if not isinstance(enum_vals, list):
            enum_vals = []

        return ParamSchema(
            name=name,
            location=location,
            type=param_type,
            format=param_format,
            enum=enum_vals,
            pattern=schema_dict.get("pattern"),
            minimum=schema_dict.get("minimum"),
            maximum=schema_dict.get("maximum"),
            required=bool(required),
            default=schema_dict.get("default"),
            properties=schema_dict.get("properties", {}),
        )

    @classmethod
    def generate_probes(cls, schema: ParamSchema) -> list[SemanticProbe]:
        """Generate schema-conforming security mutation probes tailored to the parameter schema."""
        probes: list[SemanticProbe] = []

        # -------------------------------------------------------------
        # 1. UUID Type / Format
        # -------------------------------------------------------------
        if schema.format == "uuid":
            # BOLA: probe with well-formed, non-existent UUID or secondary user UUID
            probes.append(SemanticProbe(
                attack_type="BOLA",
                payload_value="00000000-0000-0000-0000-000000000001",
                owasp_category="API1:2023",
                expected_signal=["admin", "user", "id", "created_at"],
                description="Schema-conforming UUID tampering (BOLA/IDOR)",
            ))
            # SQLi: UUID-embedded SQL canary if backend does string interpolation before cast
            probes.append(SemanticProbe(
                attack_type="SQL_INJECTION",
                payload_value="00000000-0000-0000-0000-000000000000' OR '1'='1",
                owasp_category="API8:2023",
                expected_signal=["sql", "syntax", "postgres", "sqlite", "psql", "traceback"],
                description="UUID string-interpolation SQL canary probe",
            ))
            return probes

        # -------------------------------------------------------------
        # 2. Email Format
        # -------------------------------------------------------------
        if schema.format == "email":
            # BOLA: valid email format targeting admin
            probes.append(SemanticProbe(
                attack_type="BOLA",
                payload_value="admin@example.com",
                owasp_category="API1:2023",
                expected_signal=["admin", "role", "id"],
                description="Schema-conforming email authorization override",
            ))
            # SQLi: valid RFC 5322 local-part SQL canary
            probes.append(SemanticProbe(
                attack_type="SQL_INJECTION",
                payload_value="probe.sqli'OR'1'='1@canary.local",
                owasp_category="API8:2023",
                expected_signal=["sql", "syntax", "sqlite", "psql", "traceback"],
                description="RFC 5322 compliant SQL injection canary email",
            ))
            # SSTI: valid email format with template expression
            probes.append(SemanticProbe(
                attack_type="SSTI",
                payload_value="canary.ssti.{{7*7}}@example.com",
                owasp_category="API8:2023",
                expected_signal=["49"],
                description="Schema-conforming template injection email",
            ))
            # XSS: valid email with XSS tag in alias
            probes.append(SemanticProbe(
                attack_type="XSS",
                payload_value="probe+<script>alert(1)</script>@example.com",
                owasp_category="API8:2023",
                expected_signal=["<script>alert(1)</script>"],
                description="Schema-conforming XSS canary email",
            ))
            return probes

        # -------------------------------------------------------------
        # 3. URI / URL Format
        # -------------------------------------------------------------
        if schema.format in ("uri", "url") or any(
            k in schema.name.lower() for k in ("url", "uri", "callback", "redirect", "webhook", "target")
        ):
            probes.append(SemanticProbe(
                attack_type="SSRF",
                payload_value="http://127.0.0.1:80/canary_ssrf_probe",
                owasp_category="API7:2023",
                expected_signal=["localhost", "127.0.0.1", "connection refused"],
                description="Loopback SSRF URI validation probe",
            ))
            probes.append(SemanticProbe(
                attack_type="SSRF",
                payload_value="http://169.254.169.254/latest/meta-data/",
                owasp_category="API7:2023",
                expected_signal=["ami-id", "instance-id", "security-credentials"],
                description="Cloud metadata SSRF URI probe",
            ))
            return probes

        # -------------------------------------------------------------
        # 4. Date / Date-Time Format
        # -------------------------------------------------------------
        if schema.format in ("date-time", "date"):
            # Boundary date values
            probes.append(SemanticProbe(
                attack_type="BOUNDARY_ANALYSIS",
                payload_value="1970-01-01T00:00:00Z" if schema.format == "date-time" else "1970-01-01",
                owasp_category="API8:2023",
                expected_signal=[],
                description="Epoch zero boundary date probe",
            ))
            probes.append(SemanticProbe(
                attack_type="BOUNDARY_ANALYSIS",
                payload_value="2099-12-31T23:59:59Z" if schema.format == "date-time" else "2099-12-31",
                owasp_category="API8:2023",
                expected_signal=[],
                description="Far-future boundary date probe",
            ))
            # Format injection
            probes.append(SemanticProbe(
                attack_type="SQL_INJECTION",
                payload_value="1970-01-01' OR '1'='1",
                owasp_category="API8:2023",
                expected_signal=["sql", "syntax", "sqlite", "psql", "traceback"],
                description="Date-prefixed SQL injection probe",
            ))
            return probes

        # -------------------------------------------------------------
        # 5. Integer / Number Type
        # -------------------------------------------------------------
        if schema.type in ("integer", "number"):
            # BOLA for integer IDs (e.g. /users/{id})
            probes.append(SemanticProbe(
                attack_type="BOLA",
                payload_value=1,
                owasp_category="API1:2023",
                expected_signal=["admin", "user", "id"],
                description="Integer ID BOLA probe (Root/Admin object)",
            ))
            probes.append(SemanticProbe(
                attack_type="BOLA",
                payload_value=0,
                owasp_category="API1:2023",
                expected_signal=["admin", "user", "id"],
                description="Integer ID BOLA probe (Zero index object)",
            ))
            probes.append(SemanticProbe(
                attack_type="BOLA",
                payload_value=999999,
                owasp_category="API1:2023",
                expected_signal=[],
                description="High integer boundary probe",
            ))
            # Integer Boundary / Overflow probes (API4:2023)
            probes.append(SemanticProbe(
                attack_type="INTEGER_OVERFLOW",
                payload_value=2147483647,  # INT32 MAX
                owasp_category="API4:2023",
                expected_signal=["overflow", "exception", "traceback"],
                description="Int32 maximum boundary probe",
            ))
            probes.append(SemanticProbe(
                attack_type="INTEGER_OVERFLOW",
                payload_value=-1,
                owasp_category="API4:2023",
                expected_signal=["negative", "invalid", "unhandled"],
                description="Negative integer boundary probe",
            ))
            return probes

        # -------------------------------------------------------------
        # 6. Boolean Type
        # -------------------------------------------------------------
        if schema.type == "boolean":
            probes.append(SemanticProbe(
                attack_type="MASS_ASSIGNMENT",
                payload_value=True,
                owasp_category="API3:2023",
                expected_signal=["true", "admin", "success"],
                description="Privilege elevation boolean probe",
            ))
            return probes

        # -------------------------------------------------------------
        # 7. Enum Restrictions
        # -------------------------------------------------------------
        if schema.enum:
            # Check for high-privilege enum values
            privileged_candidates = [
                val for val in schema.enum
                if str(val).lower() in ("admin", "administrator", "root", "superuser", "system", "manager")
            ]
            for priv in privileged_candidates:
                probes.append(SemanticProbe(
                    attack_type="BFLA",
                    payload_value=priv,
                    owasp_category="API5:2023",
                    expected_signal=[str(priv).lower()],
                    description=f"Privilege enum parameter override: {priv}",
                ))
            # Probe first valid enum value
            if schema.enum:
                probes.append(SemanticProbe(
                    attack_type="BOLA",
                    payload_value=schema.enum[0],
                    owasp_category="API1:2023",
                    expected_signal=[],
                    description=f"Schema-valid baseline enum: {schema.enum[0]}",
                ))
            return probes

        # -------------------------------------------------------------
        # 8. Generic String Type (Comprehensive security mutations)
        # -------------------------------------------------------------
        probes.extend([
            SemanticProbe(
                attack_type="BOLA",
                payload_value="admin",
                owasp_category="API1:2023",
                expected_signal=["admin", "id", "user"],
                description="String administrative identity override",
            ),
            SemanticProbe(
                attack_type="SQL_INJECTION",
                payload_value="1' OR '1'='1",
                owasp_category="API8:2023",
                expected_signal=["sql", "syntax", "sqlite", "psql", "traceback"],
                description="Standard SQL injection canary probe",
            ),
            SemanticProbe(
                attack_type="PATH_TRAVERSAL",
                payload_value="../../../../etc/passwd",
                owasp_category="API8:2023",
                expected_signal=["root:x:0:0", "daemon:x:", "[boot loader]"],
                description="POSIX path traversal canary probe",
            ),
            SemanticProbe(
                attack_type="PATH_TRAVERSAL",
                payload_value=r"..\..\..\..\windows\win.ini",
                owasp_category="API8:2023",
                expected_signal=["[extensions]", "[fonts]", "[mci extensions]"],
                description="Windows path traversal canary probe",
            ),
            SemanticProbe(
                attack_type="SSTI",
                payload_value="{{7*7}}",
                owasp_category="API8:2023",
                expected_signal=["49"],
                description="Server-Side Template Injection canary probe",
            ),
            SemanticProbe(
                attack_type="NOSQL_INJECTION",
                payload_value='{"$ne": null}',
                owasp_category="API8:2023",
                expected_signal=["$ne", "mongo", "bson", "syntaxerror"],
                description="NoSQL operator injection probe",
            ),
            SemanticProbe(
                attack_type="XSS",
                payload_value="<script>alert(1)</script>",
                owasp_category="API8:2023",
                expected_signal=["<script>alert(1)</script>"],
                description="Reflected XSS script tag probe",
            ),
        ])

        return probes

    @classmethod
    def generate_schema_valid_sample(cls, schema: dict[str, Any]) -> Any:
        """Construct a minimal schema-valid JSON object to satisfy required fields."""
        if not isinstance(schema, dict):
            return "valid_string"

        schema_type = str(schema.get("type", "object")).lower()
        if schema_type == "object":
            obj: dict[str, Any] = {}
            props = schema.get("properties", {})
            required_keys = schema.get("required", [])

            for prop_name, prop_def in props.items():
                if isinstance(prop_def, dict):
                    # Always include required fields, and include top 5 non-required fields
                    if prop_name in required_keys or len(obj) < 6:
                        obj[prop_name] = cls.generate_schema_valid_sample(prop_def)
            return obj

        if schema_type == "array":
            items_schema = schema.get("items", {"type": "string"})
            return [cls.generate_schema_valid_sample(items_schema)]

        if schema_type in ("integer", "number"):
            return 1

        if schema_type == "boolean":
            return False

        # String formats
        fmt = schema.get("format")
        if fmt == "uuid":
            return str(uuid.uuid4())
        if fmt == "email":
            return "user@example.com"
        if fmt == "uri":
            return "https://example.com"
        if fmt in ("date-time", "datetime"):
            return "2026-01-01T00:00:00Z"
        if fmt == "date":
            return "2026-01-01"

        if schema.get("enum"):
            return schema["enum"][0]

        return "sample_text"
