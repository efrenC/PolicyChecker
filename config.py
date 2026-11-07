"""Service settings and limits, kept in one place."""

import os
from pathlib import Path

# How many datasets one request may compare.
MIN_DATASETS = 2
MAX_DATASETS = 4

# Field and request size limits (guards against oversized or abusive input).
MAX_NAME_LENGTH = 200
MAX_DESCRIPTION_LENGTH = 2000
MAX_REQUEST_BYTES = 16 * 1024

# Policy link checks.
LINK_TIMEOUT_SECONDS = 5.0
MAX_REDIRECTS = 3

# Where audit entries are appended (one JSON object per line).
AUDIT_LOG_PATH = Path(os.getenv("POLICYCHECKER_AUDIT_LOG", "audit_log.jsonl"))

# Longest copy of a rejected request kept in the audit log.
MAX_AUDITED_INPUT_CHARS = 8000

# Set POLICYCHECKER_SKIP_LINK_CHECK=1 to skip network calls (offline demos).
SKIP_LINK_CHECK = os.getenv("POLICYCHECKER_SKIP_LINK_CHECK") == "1"

# Set POLICYCHECKER_DISABLE_DOCS=1 to hide /docs, /redoc and /openapi.json in production.
ENABLE_DOCS = os.getenv("POLICYCHECKER_DISABLE_DOCS") != "1"
