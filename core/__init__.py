from __future__ import annotations

from .auth_manager import AuthConfig, AuthManager
from .benchmark_harness import (
    AuthPreflightResult,
    BenchmarkEvaluator,
    ClassEvaluationMetrics,
    CrossClassFalsePositive,
    FindingTraceRecord,
    GroundTruthExpectation,
    GroundTruthManifest,
    NoiseControlEndpoint,
    OperationalErrorRecord,
    SkippedPairInfo,
    load_ground_truth_manifest,
    normalize_endpoint,
    normalize_vuln_class,
    run_auth_preflight,
    snapshot_files_integrity,
    verify_isolation,
)
from .bola_validator import (
    BolaValidator,
    BolaVerdict,
    extract_user_hint_from_token,
)
from .boundary_validator import (
    BoundaryValidator,
    BoundaryVerdict,
)
from .ssti_validator import (
    SstiDifferentialProbes,
    SstiValidator,
    SstiVerdict,
    build_differential_ssti_probes,
)
from .callback_verifier import (
    CallbackEvent,
    CallbackVerifier,
    LocalCallbackListener,
)
from .curl_builder import (
    build_curl_command,
    build_curl_from_finding,
    build_curl_dual,
    build_curl_dual_from_finding,
)
from .har_parser import HARSeed, SeedCorpus, parse_har_file
from .safety_cleanup import CleanupTracker, CreatedResource, get_audit_headers
from .evidence import (
    verify_deep_state_persistence,
)
try:
    from .concurrency_fuzzer import (
        ConcurrencyBurstResult,
        ConcurrencyFuzzer,
    )
except (ImportError, ValueError):
    try:
        from core.concurrency_fuzzer import (  # type: ignore
            ConcurrencyBurstResult,
            ConcurrencyFuzzer,
        )
    except Exception:
        ConcurrencyBurstResult = None  # type: ignore
        ConcurrencyFuzzer = None  # type: ignore
from .dependency_graph import (
    ApiDependencyGraph,
    ConsumerCandidate,
    ProducerCandidate,
)
from .discovery import ApiDiscoveryEngine, DiscoveryResult, discover_api
from .evidence import (
    CircuitBreakerTrippedError,
    ConfirmationEngine,
    ConfirmationResult,
    DetectionResult,
    Evidence,
    Finding,
    LIFECYCLE_RANK,
    Observation,
    RequestScheduler,
    ResponseObservation,
    ResponseSnapshot,
    ValidationDecision,
    build_finding_from_observations,
    compare_responses,
    confirmation_result,
    content_hash,
    merge_findings,
    redact_headers,
    sanitize_body,
    snapshot_response,
    stable_finding_id,
    summarize_lifecycle,
    synthesize_observation_from_finding,
)
from .feedback_engine import (
    FeedbackAnalysisResult,
    FeedbackAnalyzer,
    FieldValidationFailure,
)
from .header_tamper_fuzzer import (
    HeaderTamperFuzzer,
    HeaderTamperProbe,
    HeaderTamperResult,
)
from .path_manager import ProjectPaths, resolve_project_root, safe_project_path
from .schema_validator import (
    PurePythonSchemaValidator,
    install_jsonschema_rs_shim_if_needed,
)
from .session_keeper import (
    AuthAutomationConfig,
    SessionKeeper,
    decode_jwt_unverified,
    is_jwt_expired_or_expiring,
)
from .graphql_advanced_auditor import (
    GraphQLAdvancedAuditor,
    GraphQLAuditResult,
)
from .proxy_rotator import (
    ProxyRotator,
    ProxyState,
)
from .remediation_engine import (
    RemediationEngine,
    RemediationSnippet,
)
from .pii_detector import (
    PiiDetector,
    PiiMatch,
    PiiScanResult,
    luhn_checksum_valid,
)
from .reporter import OWASP_METADATA, SecurityReporter, compute_tamper_signature
from .resource_exhaustion_fuzzer import (
    ResourceExhaustionFuzzer,
    ResourceProbeResult,
)
from .result_manager import ResultManager, make_run_id
from .run_state import (
    DEFAULT_ERROR_SIGNALS,
    MAX_ATTEMPTS_PER_FINGERPRINT,
    RunState,
    SEVERITY_BY_STATUS,
    extract_response_elapsed_ms,
    normalize_auth_header,
    parse_tokens_env,
)
from .schema_converter import (
    convert_any_to_openapi,
    convert_file_to_openapi,
    detect_schema_format,
    har_to_openapi,
    postman_to_openapi,
)
from .schema_manager import SchemaManager, load_schema
from .semantic_mutator import (
    ParamSchema,
    SemanticMutationEngine,
    SemanticProbe,
)
from .target_manager import TargetConfig, TargetManager, TargetRegistry, target_config
from .token_verifier import TokenInspection, TokenVerifier
from .validation_policy import (
    ALLOWED_SEVERITIES_BY_OUTCOME,
    CANDIDATE_MAX_CONFIDENCE,
    CANDIDATE_NO_BASELINE_MAX_CONFIDENCE,
    CONFIRMED_MIN_CONFIDENCE,
    INCONCLUSIVE_MAX_CONFIDENCE,
    NormalizedVerdict,
    REJECTED_MAX_CONFIDENCE,
    VALID_OUTCOMES,
    normalize_validation_verdict,
    sanitize_confidence,
)
from .workflow_engine import (
    StepExecutionResult,
    WorkflowDefinition,
    WorkflowExecutionReport,
    WorkflowRunner,
    WorkflowStep,
    interpolate_template,
    resolve_selector,
)

__all__ = [
    "ApiDependencyGraph",
    "ApiDiscoveryEngine",
    "AuthConfig",
    "AuthManager",
    "AuthPreflightResult",
    "BenchmarkEvaluator",
    "ClassEvaluationMetrics",
    "CrossClassFalsePositive",
    "FindingTraceRecord",
    "GroundTruthExpectation",
    "GroundTruthManifest",
    "NoiseControlEndpoint",
    "OperationalErrorRecord",
    "SkippedPairInfo",
    "load_ground_truth_manifest",
    "normalize_endpoint",
    "normalize_vuln_class",
    "run_auth_preflight",
    "snapshot_files_integrity",
    "verify_isolation",
    "BolaValidator",
    "BolaVerdict",
    "BoundaryValidator",
    "BoundaryVerdict",
    "CallbackEvent",
    "CallbackVerifier",
    "CircuitBreakerTrippedError",
    "ConcurrencyBurstResult",
    "ConcurrencyFuzzer",
    "ConfirmationEngine",
    "ConfirmationResult",
    "ConsumerCandidate",
    "DetectionResult",
    "DiscoveryResult",
    "Evidence",
    "FeedbackAnalysisResult",
    "FeedbackAnalyzer",
    "FieldValidationFailure",
    "Finding",
    "LIFECYCLE_RANK",
    "Observation",
    "ValidationDecision",
    "HeaderTamperFuzzer",
    "HeaderTamperProbe",
    "HeaderTamperResult",
    "LocalCallbackListener",
    "OWASP_METADATA",
    "ParamSchema",
    "PiiDetector",
    "PiiMatch",
    "PiiScanResult",
    "ProducerCandidate",
    "ResourceExhaustionFuzzer",
    "ResourceProbeResult",
    "SecurityReporter",
    "RequestScheduler",
    "ResponseObservation",
    "ResponseSnapshot",
    "SemanticMutationEngine",
    "SemanticProbe",
    "SstiDifferentialProbes",
    "SstiValidator",
    "SstiVerdict",
    "StepExecutionResult",
    "TargetConfig",
    "TargetManager",
    "TargetRegistry",
    "ProjectPaths",
    "ResultManager",
    "SchemaManager",
    "TokenInspection",
    "TokenVerifier",
    "ALLOWED_SEVERITIES_BY_OUTCOME",
    "CANDIDATE_MAX_CONFIDENCE",
    "CANDIDATE_NO_BASELINE_MAX_CONFIDENCE",
    "CONFIRMED_MIN_CONFIDENCE",
    "INCONCLUSIVE_MAX_CONFIDENCE",
    "NormalizedVerdict",
    "REJECTED_MAX_CONFIDENCE",
    "VALID_OUTCOMES",
    "normalize_validation_verdict",
    "sanitize_confidence",
    "WorkflowDefinition",
    "WorkflowExecutionReport",
    "WorkflowRunner",
    "WorkflowStep",
    "build_finding_from_observations",
    "compare_responses",
    "compute_tamper_signature",
    "confirmation_result",
    "content_hash",
    "convert_any_to_openapi",
    "convert_file_to_openapi",
    "detect_schema_format",
    "discover_api",
    "extract_user_hint_from_token",
    "har_to_openapi",
    "interpolate_template",
    "load_schema",
    "luhn_checksum_valid",
    "make_run_id",
    "merge_findings",
    "postman_to_openapi",
    "redact_headers",
    "resolve_project_root",
    "resolve_selector",
    "safe_project_path",
    "sanitize_body",
    "snapshot_response",
    "stable_finding_id",
    "summarize_lifecycle",
    "synthesize_observation_from_finding",
    "target_config",
    "build_curl_command",
    "build_curl_from_finding",
    "build_curl_dual",
    "build_curl_dual_from_finding",
    "build_differential_ssti_probes",
    "HARSeed",
    "SeedCorpus",
    "parse_har_file",
    "CleanupTracker",
    "CreatedResource",
    "get_audit_headers",
    "verify_deep_state_persistence",
    "PurePythonSchemaValidator",
    "install_jsonschema_rs_shim_if_needed",
    "AuthAutomationConfig",
    "SessionKeeper",
    "decode_jwt_unverified",
    "is_jwt_expired_or_expiring",
    "GraphQLAdvancedAuditor",
    "GraphQLAuditResult",
    "ProxyRotator",
    "ProxyState",
    "RemediationEngine",
    "RemediationSnippet",
    "DEFAULT_ERROR_SIGNALS",
    "MAX_ATTEMPTS_PER_FINGERPRINT",
    "RunState",
    "SEVERITY_BY_STATUS",
    "extract_response_elapsed_ms",
    "normalize_auth_header",
    "parse_tokens_env",
]
