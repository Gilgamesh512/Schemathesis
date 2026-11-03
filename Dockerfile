# ==============================================================================
# Enterprise API Security Fuzzing Scanner
# Multi-stage secure Docker container for CI/CD DevSecOps pipelines
# ==============================================================================

FROM python:3.12-slim-bookworm

LABEL maintainer="Schemathesis API Security Team"
LABEL description="Enterprise automated API security testing and fuzzing engine"
LABEL version="2.0.0"

# Set environment flags
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    DEBIAN_FRONTEND=noninteractive

# Install essential runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create dedicated non-root application user
RUN groupadd -g 1000 scanner && \
    useradd -u 1000 -g scanner -m -s /bin/bash scanner

WORKDIR /app

# Install Python requirements
COPY requirements.txt requirements-dev.txt ./
RUN pip install --upgrade pip && \
    pip install -r requirements.txt

# Copy source tree and configuration
COPY . /app

# Ensure workspace ownership and directory permissions for non-root execution
RUN mkdir -p /app/results /app/targets /app/config && \
    chown -R scanner:scanner /app

USER scanner

# Default volume mount points for scan results and targets
VOLUME ["/app/results", "/app/targets"]

ENTRYPOINT ["python", "run_all.py"]
CMD ["--help"]
