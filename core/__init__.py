from __future__ import annotations

from .auth_manager import AuthConfig, AuthManager
from .callback_verifier import (
    CallbackEvent,
    CallbackVerifier,
    LocalCallbackListener,
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
    ConfirmationEngine,
    ConfirmationResult,
    Evidence,
    Finding,
    RequestScheduler,
    ResponseObservation,
    ResponseSnapshot,
    compare_responses,
    confirmation_result,
    content_hash,
    redact_headers,
    snapshot_response,
    stable_finding_id,
)
from .feedback_engine import (
    FeedbackAnalysisResult,
    FeedbackAnalyzer,
    FieldValidationFailure,
)
from .path_manager import ProjectPaths, resolve_project_root, safe_project_path
from .reporter import OWASP_METADATA, SecurityReporter
from .result_manager import ResultManager, make_run_id
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
    "CallbackEvent",
    "CallbackVerifier",
    "ConcurrencyBurstResult",
    "ConcurrencyFuzzer",
    "ConfirmationEngine",
    "ConfirmationResult",
    "ConsumerCandidate",
    "DiscoveryResult",
    "Evidence",
    "FeedbackAnalysisResult",
    "FeedbackAnalyzer",
    "FieldValidationFailure",
    "Finding",
    "LocalCallbackListener",
    "OWASP_METADATA",
    "ParamSchema",
    "ProducerCandidate",
    "SecurityReporter",
    "RequestScheduler",
    "ResponseObservation",
    "ResponseSnapshot",
    "SemanticMutationEngine",
    "SemanticProbe",
    "StepExecutionResult",
    "TargetConfig",
    "TargetManager",
    "TargetRegistry",
    "ProjectPaths",
    "ResultManager",
    "SchemaManager",
    "TokenInspection",
    "TokenVerifier",
    "WorkflowDefinition",
    "WorkflowExecutionReport",
    "WorkflowRunner",
    "WorkflowStep",
    "compare_responses",
    "confirmation_result",
    "content_hash",
    "convert_any_to_openapi",
    "convert_file_to_openapi",
    "detect_schema_format",
    "discover_api",
    "har_to_openapi",
    "interpolate_template",
    "load_schema",
    "make_run_id",
    "postman_to_openapi",
    "redact_headers",
    "resolve_project_root",
    "resolve_selector",
    "safe_project_path",
    "snapshot_response",
    "stable_finding_id",
    "target_config",
]
