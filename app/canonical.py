import hashlib
import json
import re
import secrets
from typing import Any, Optional, Tuple

TRACEPARENT_REGEX = re.compile(r"^00-([0-9a-fA-F]{32})-([0-9a-fA-F]{16})-([0-9a-fA-F]{2})$")


def canonical_json(data: Any) -> str:
    """Recursively formats data as canonical compact JSON with sorted keys."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(data: str | bytes) -> str:
    """Computes lowercase SHA-256 hex digest of string or bytes."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest().lower()


def compute_arguments_digest(arguments: dict) -> str:
    """Computes lowercase SHA-256 hex over recursively key-sorted compact JSON arguments."""
    return sha256_hex(canonical_json(arguments))


def generate_trace_id() -> str:
    """Generates a nonzero 32-character lowercase hex trace ID."""
    while True:
        tid = secrets.token_hex(16).lower()
        if tid != "0" * 32:
            return tid


def generate_span_id() -> str:
    """Generates a nonzero 16-character lowercase hex span ID."""
    while True:
        sid = secrets.token_hex(8).lower()
        if sid != "0" * 16:
            return sid


def parse_traceparent(traceparent: Optional[str]) -> Optional[Tuple[str, str, str]]:
    """
    Parses W3C traceparent header.
    Returns (trace_id, parent_span_id, trace_flags) if valid, else None.
    """
    if not traceparent:
        return None
    match = TRACEPARENT_REGEX.match(traceparent.strip())
    if not match:
        return None
    trace_id, span_id, flags = match.groups()
    trace_id = trace_id.lower()
    span_id = span_id.lower()
    flags = flags.lower()
    if trace_id == "0" * 32 or span_id == "0" * 16:
        return None
    return trace_id, span_id, flags


def format_traceparent(trace_id: str, span_id: str, flags: str = "01") -> str:
    """Formats a W3C traceparent header string."""
    return f"00-{trace_id.lower()}-{span_id.lower()}-{flags}"
