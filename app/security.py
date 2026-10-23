from typing import Any, Dict, List, Optional
import jsonschema

SENSITIVE_KEYS = {
    "accesstoken",
    "privatenote",
    "authorization",
    "password",
    "secret",
    "token",
    "api_key",
    "apikey",
    "credentials",
}


def redact_sensitive(obj: Any) -> Any:
    """Recursively redacts sensitive keys from dictionaries or lists."""
    if isinstance(obj, dict):
        result = {}
        for k, v in obj.items():
            if str(k).lower().replace("_", "").replace("-", "") in SENSITIVE_KEYS:
                result[k] = "[REDACTED]"
            else:
                result[k] = redact_sensitive(v)
        return result
    elif isinstance(obj, list):
        return [redact_sensitive(item) for item in obj]
    return obj


def validate_arguments_against_schema(schema: Optional[Dict[str, Any]], arguments: Dict[str, Any]) -> bool:
    """Validates arguments against a JSON schema if schema is provided."""
    if not schema or not isinstance(schema, dict):
        return True
    try:
        jsonschema.validate(instance=arguments, schema=schema)
        return True
    except Exception:
        return False
