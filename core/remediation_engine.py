"""Framework-Specific Remediation Snippet Engine (OWASP API Security Top 10).

Provides actionable, production-ready, idiomatic code patches for FastAPI, Spring Boot,
NestJS, Express.js, and Django REST Framework to replace generic text advice with concrete
remediation snippets.
"""

from __future__ import annotations

import re
from typing import Any, Optional
from pydantic import BaseModel


class RemediationSnippet(BaseModel):
    framework: str
    owasp_category: str
    title: str
    explanation: str
    vulnerable_example: str
    secure_example: str


# Catalog of idiomatic, framework-specific code patches
REMEDIATION_CATALOG: dict[tuple[str, str], RemediationSnippet] = {
    # --------------------------------------------------------------------------
    # API1:2023 - BOLA / IDOR
    # --------------------------------------------------------------------------
    ("fastapi", "API1:2023"): RemediationSnippet(
        framework="FastAPI",
        owasp_category="API1:2023",
        title="Enforce Data-Access Layer User Scoping (FastAPI / SQLAlchemy)",
        explanation="Always tie resource queries to the authenticated user's ID rather than querying purely by object ID.",
        vulnerable_example=(
            "@router.get('/orders/{order_id}')\n"
            "def get_order(order_id: int, db: Session = Depends(get_db)):\n"
            "    # VULNERABLE: Any authenticated user can view any order\n"
            "    return db.query(Order).filter(Order.id == order_id).first()"
        ),
        secure_example=(
            "@router.get('/orders/{order_id}')\n"
            "def get_order(order_id: int, current_user: User = Depends(get_current_active_user), db: Session = Depends(get_db)):\n"
            "    # SECURE: Resource query scoped to current user ownership\n"
            "    order = db.query(Order).filter(Order.id == order_id, Order.owner_id == current_user.id).first()\n"
            "    if not order:\n"
            "        raise HTTPException(status_code=404, detail='Order not found')\n"
            "    return order"
        ),
    ),
    ("spring_boot", "API1:2023"): RemediationSnippet(
        framework="Spring Boot",
        owasp_category="API1:2023",
        title="Method-Level Authorization with SpEL & Ownership Check",
        explanation="Apply Spring Security @PreAuthorize to ensure resource owner matches principal.",
        vulnerable_example=(
            "@GetMapping('/orders/{id}')\n"
            "public Order getOrder(@PathVariable Long id) {\n"
            "    // VULNERABLE: Direct repository fetch without user verification\n"
            "    return orderRepository.findById(id).orElseThrow();\n"
            "}"
        ),
        secure_example=(
            "@PreAuthorize('#order.ownerUsername == authentication.name or hasRole(\"ADMIN\")')\n"
            "@GetMapping('/orders/{id}')\n"
            "public Order getOrder(@PathVariable Long id, @AuthenticationPrincipal UserDetails user) {\n"
            "    return orderRepository.findByIdAndOwnerId(id, user.getId())\n"
            "        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));\n"
            "}"
        ),
    ),
    ("nestjs", "API1:2023"): RemediationSnippet(
        framework="NestJS",
        owasp_category="API1:2023",
        title="Custom Ownership Guard / Service Scoping",
        explanation="Inject user from Request context and filter queries in TypeORM/Prisma repository.",
        vulnerable_example=(
            "@Get(':id')\n"
            "async findOne(@Param('id') id: string) {\n"
            "  // VULNERABLE: Returns entity regardless of caller identity\n"
            "  return this.orderService.findById(id);\n"
            "}"
        ),
        secure_example=(
            "@UseGuards(JwtAuthGuard, ResourceOwnerGuard)\n"
            "@Get(':id')\n"
            "async findOne(@Param('id') id: string, @Req() req) {\n"
            "  // SECURE: Enforce owner constraint at repository query\n"
            "  const order = await this.orderService.findOne({ where: { id, userId: req.user.id } });\n"
            "  if (!order) throw new NotFoundException();\n"
            "  return order;\n"
            "}"
        ),
    ),
    ("express", "API1:2023"): RemediationSnippet(
        framework="Express.js",
        owasp_category="API1:2023",
        title="Query Filtering by req.user.id",
        explanation="Combine MongoDB / SQL query with authenticated user session ID.",
        vulnerable_example=(
            "app.get('/api/orders/:id', auth, async (req, res) => {\n"
            "  const order = await Order.findById(req.params.id);\n"
            "  res.json(order);\n"
            "});"
        ),
        secure_example=(
            "app.get('/api/orders/:id', auth, async (req, res) => {\n"
            "  const order = await Order.findOne({ _id: req.params.id, userId: req.user.id });\n"
            "  if (!order) return res.status(404).json({ error: 'Order not found' });\n"
            "  res.json(order);\n"
            "});"
        ),
    ),

    # --------------------------------------------------------------------------
    # API2:2023 - Broken Authentication (JWT)
    # --------------------------------------------------------------------------
    ("fastapi", "API2:2023"): RemediationSnippet(
        framework="FastAPI",
        owasp_category="API2:2023",
        title="Strict Algorithm Whitelist & Expiration Enforcement in PyJWT",
        explanation="Explicitly specify algorithms=['HS256'] and require 'exp' claim.",
        vulnerable_example=(
            "# VULNERABLE: jwt.decode without algorithm enforcement or signature verification\n"
            "payload = jwt.decode(token, options={'verify_signature': False})"
        ),
        secure_example=(
            "# SECURE: Whitelist algorithms, verify signature & enforce expiration\n"
            "payload = jwt.decode(\n"
            "    token,\n"
            "    SECRET_KEY,\n"
            "    algorithms=['HS256'],\n"
            "    options={'require': ['exp', 'sub'], 'verify_exp': True}\n"
            ")"
        ),
    ),
    ("spring_boot", "API2:2023"): RemediationSnippet(
        framework="Spring Boot",
        owasp_category="API2:2023",
        title="Spring Security OAuth2 Resource Server JWT Validator",
        explanation="Enforce strict clock skew and signature verification in JwtDecoder.",
        vulnerable_example=(
            "// Custom parser missing algorithm checks\n"
            "Claims claims = Jwts.parser().setSigningKey(key).parseClaimsJws(token).getBody();"
        ),
        secure_example=(
            "@Bean\n"
            "public JwtDecoder jwtDecoder() {\n"
            "    NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withSecretKey(secretKey)\n"
            "        .macAlgorithm(MacAlgorithm.HS256).build();\n"
            "    OAuth2TokenValidator<Jwt> withExp = new JwtTimestampValidator(Duration.ofSeconds(60));\n"
            "    jwtDecoder.setJwtValidator(withExp);\n"
            "    return jwtDecoder;\n"
            "}"
        ),
    ),

    # --------------------------------------------------------------------------
    # API3:2023 - BOPLA / Mass Assignment
    # --------------------------------------------------------------------------
    ("fastapi", "API3:2023"): RemediationSnippet(
        framework="FastAPI",
        owasp_category="API3:2023",
        title="Forbid Extra Fields in Pydantic v2 DTOs",
        explanation="Set model_config = ConfigDict(extra='forbid') on input request models.",
        vulnerable_example=(
            "class UpdateProfile(BaseModel):\n"
            "    name: str\n"
            "    # VULNERABLE: Accepts is_admin or role if passed in JSON body\n"
            "    pass"
        ),
        secure_example=(
            "class UpdateProfile(BaseModel):\n"
            "    model_config = ConfigDict(extra='forbid')\n"
            "    name: str\n"
            "    bio: Optional[str] = None\n"
            "    # Any unexpected fields (e.g. role, balance) trigger HTTP 422"
        ),
    ),
    ("nestjs", "API3:2023"): RemediationSnippet(
        framework="NestJS",
        owasp_category="API3:2023",
        title="Global ValidationPipe with whitelist & forbidNonWhitelisted",
        explanation="Configure global validation pipe to automatically strip or reject unknown fields.",
        vulnerable_example=(
            "// VULNERABLE: Direct body assignment\n"
            "@Post() create(@Body() body: any) { return this.svc.create(body); }"
        ),
        secure_example=(
            "app.useGlobalPipes(new ValidationPipe({\n"
            "  whitelist: true,\n"
            "  forbidNonWhitelisted: true,\n"
            "  transform: true,\n"
            "}));"
        ),
    ),

    # --------------------------------------------------------------------------
    # API4:2023 - Unrestricted Resource Consumption & GraphQL Batching
    # --------------------------------------------------------------------------
    ("fastapi", "API4:2023"): RemediationSnippet(
        framework="FastAPI",
        owasp_category="API4:2023",
        title="Rate-Limiting with SlowAPI & Maximum Payload Constraints",
        explanation="Add SlowAPI rate limiter and enforce pagination caps (e.g., limit <= 100).",
        vulnerable_example=(
            "@router.get('/items')\n"
            "def list_items(limit: int = 100000):  # VULNERABLE: Uncapped query\n"
            "    return db.query(Item).limit(limit).all()"
        ),
        secure_example=(
            "from slowapi import Limiter\n"
            "limiter = Limiter(key_func=get_remote_address)\n\n"
            "@router.get('/items')\n"
            "@limiter.limit('30/minute')\n"
            "def list_items(request: Request, limit: int = Query(default=20, le=100)):\n"
            "    return db.query(Item).limit(limit).all()"
        ),
    ),
    ("nestjs", "API4:2023"): RemediationSnippet(
        framework="NestJS",
        owasp_category="API4:2023",
        title="ThrottlerModule & Apollo allowBatchedHttpRequests: false",
        explanation="Disable query batching in Apollo Server and add ThrottlerGuard.",
        vulnerable_example=(
            "GraphQLModule.forRoot({\n"
            "  driver: ApolloDriver,\n"
            "  // Default allows batching\n"
            "})"
        ),
        secure_example=(
            "GraphQLModule.forRoot({\n"
            "  driver: ApolloDriver,\n"
            "  allowBatchedHttpRequests: false, // SECURE: Disable query batching\n"
            "  plugins: [responseCachePlugin()],\n"
            "});\n"
            "// + ThrottlerModule.forRoot([{ ttl: 60000, limit: 60 }])"
        ),
    ),

    # --------------------------------------------------------------------------
    # API7:2023 - SSRF (Server-Side Request Forgery)
    # --------------------------------------------------------------------------
    ("fastapi", "API7:2023"): RemediationSnippet(
        framework="FastAPI",
        owasp_category="API7:2023",
        title="IP Whitelisting & Private Range Rejection in URL Fetching",
        explanation="Resolve host DNS before requesting and reject private/loopback/link-local CIDRs.",
        vulnerable_example=(
            "@router.post('/fetch-url')\n"
            "def fetch(url: str):\n"
            "    # VULNERABLE: Blindly fetches internal resources / AWS metadata\n"
            "    return requests.get(url).text"
        ),
        secure_example=(
            "import ipaddress, socket, urllib.parse\n"
            "def safe_fetch(url: str):\n"
            "    hostname = urllib.parse.urlparse(url).hostname\n"
            "    ip = ipaddress.ip_address(socket.gethostbyname(hostname))\n"
            "    if ip.is_private or ip.is_loopback or ip.is_link_local:\n"
            "        raise HTTPException(status_code=400, detail='Internal destinations prohibited')\n"
            "    return httpx.get(url, timeout=5.0).text"
        ),
    ),
}


class RemediationEngine:
    """Infers framework and resolves concrete code patches."""

    @classmethod
    def detect_framework(
        cls,
        headers: Optional[dict[str, Any]] = None,
        body: str = "",
        framework_hint: str = "",
    ) -> str:
        """Infer backend framework from headers, error signatures, or hints."""
        hint_lower = (framework_hint or "").lower()
        if "fastapi" in hint_lower or "pydantic" in hint_lower:
            return "fastapi"
        if "spring" in hint_lower:
            return "spring_boot"
        if "nestjs" in hint_lower or "class-validator" in hint_lower:
            return "nestjs"

        hdrs = {k.lower(): str(v).lower() for k, v in (headers or {}).items()}
        server = hdrs.get("server", "")
        x_powered = hdrs.get("x-powered-by", "")

        if "uvicorn" in server or "fastapi" in server:
            return "fastapi"
        if "express" in x_powered:
            return "express"
        if "nestjs" in x_powered:
            return "nestjs"
        if "tomcat" in server or "spring" in server or "coyote" in server:
            return "spring_boot"

        body_lower = body.lower()
        if "pydantic" in body_lower or "field required" in body_lower or "fastapi" in body_lower:
            return "fastapi"
        if "org.springframework" in body_lower or "whitelabel error page" in body_lower:
            return "spring_boot"
        if "nest" in body_lower or "class-validator" in body_lower:
            return "nestjs"

        return "fastapi"  # Default to modern FastAPI reference

    @classmethod
    def get_snippet(
        cls,
        owasp_category: str,
        framework: Optional[str] = None,
        headers: Optional[dict[str, Any]] = None,
        body: str = "",
        framework_hint: str = "",
    ) -> Optional[RemediationSnippet]:
        """Lookup framework-specific remediation snippet for an OWASP category."""
        target_fw = framework or cls.detect_framework(headers=headers, body=body, framework_hint=framework_hint)
        # Normalize category
        cat_match = re.search(r"API\d+:2023", owasp_category.upper())
        norm_cat = cat_match.group(0) if cat_match else owasp_category

        # Direct match
        key = (target_fw, norm_cat)
        if key in REMEDIATION_CATALOG:
            return REMEDIATION_CATALOG[key]

        # Fallback to fastapi for this category
        fallback_key = ("fastapi", norm_cat)
        if fallback_key in REMEDIATION_CATALOG:
            return REMEDIATION_CATALOG[fallback_key]

        return None
