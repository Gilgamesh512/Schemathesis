"""pytest root configuration.

Ensures that the environment resilience shim is activated before any
tests or third-party packages (like schemathesis) are loaded.
"""

import sys
from pathlib import Path

# Ensure project root is in sys.path
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Install pure-Python fallback shim if needed
try:
    from core.schema_validator import install_jsonschema_rs_shim_if_needed
    install_jsonschema_rs_shim_if_needed()
except Exception:
    pass
