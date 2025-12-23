from .patterns import SECRETS_PATTERNS, SEVERITY_LOW, CONFIDENCE_LOW

def get_severity(secret_type: str) -> str:
    if secret_type in SECRETS_PATTERNS:
        return SECRETS_PATTERNS[secret_type].severity
    return SEVERITY_LOW

def get_default_confidence(secret_type: str) -> str:
    if secret_type in SECRETS_PATTERNS:
        return SECRETS_PATTERNS[secret_type].confidence
    return CONFIDENCE_LOW
