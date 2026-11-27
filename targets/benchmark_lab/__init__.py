"""Deterministic local HTTP benchmark lab for P1.6 Ground Truth evaluation."""

from .server import (
    ALICE_EMAIL,
    ALICE_ID,
    BENCHMARK_LAB_DIR,
    BOB_EMAIL,
    BOB_ID,
    BenchmarkLabServer,
    GROUND_TRUTH_PATH,
    OPENAPI_SPEC_PATH,
    build_lab_auth_headers,
    make_lab_jwt,
)

__all__ = [
    "ALICE_EMAIL",
    "ALICE_ID",
    "BENCHMARK_LAB_DIR",
    "BOB_EMAIL",
    "BOB_ID",
    "BenchmarkLabServer",
    "GROUND_TRUTH_PATH",
    "OPENAPI_SPEC_PATH",
    "build_lab_auth_headers",
    "make_lab_jwt",
]
