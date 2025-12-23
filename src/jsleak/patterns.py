import re
from typing import Dict, Pattern, NamedTuple, Optional

class PatternConfig(NamedTuple):
    pattern: Pattern
    severity: str
    confidence: str # HIGH, MEDIUM, LOW (Default confidence for this pattern)

# Severity Levels
SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH = "HIGH"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_LOW = "LOW"

# Confidence Levels
CONFIDENCE_HIGH = "HIGH"
CONFIDENCE_MEDIUM = "MEDIUM"
CONFIDENCE_LOW = "LOW"

# Compiled regex patterns with severity and default confidence
SECRETS_PATTERNS: Dict[str, PatternConfig] = {
    "AWS Access Key": PatternConfig(
        re.compile(r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"),
        SEVERITY_HIGH,
        CONFIDENCE_HIGH
    ),
    "AWS Secret Key": PatternConfig(
        re.compile(r"(?i)aws_?(?:secret)?_?(?:access)?_?key(?:_id)?\s*[:=]\s*[\"\']([A-Za-z0-9/+=]{40})[\"\']"),
        SEVERITY_HIGH,
        CONFIDENCE_HIGH
    ),
    "Generic API Key": PatternConfig(
        re.compile(r"(?i)(?:api_?key|access_?token|auth_?token|client_?secret)\s*[:=]\s*[\"\']([a-zA-Z0-9_\-]{16,64})[\"\']"),
        SEVERITY_MEDIUM,
        CONFIDENCE_LOW # Generic requires context validation to bump to MEDIUM/HIGH
    ),
    "JWT Token": PatternConfig(
        re.compile(r"eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}"),
        SEVERITY_MEDIUM,
        CONFIDENCE_HIGH # Structure is very specific
    ),
    "RSA Private Key": PatternConfig(
        re.compile(r"-----BEGIN RSA PRIVATE KEY-----"),
        SEVERITY_CRITICAL,
        CONFIDENCE_HIGH
    ),
    "EC Private Key": PatternConfig(
        re.compile(r"-----BEGIN EC PRIVATE KEY-----"),
        SEVERITY_CRITICAL,
        CONFIDENCE_HIGH
    ),
    "DSA Private Key": PatternConfig(
        re.compile(r"-----BEGIN DSA PRIVATE KEY-----"),
        SEVERITY_CRITICAL,
        CONFIDENCE_HIGH
    ),
    "OPENSSH Private Key": PatternConfig(
        re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----"),
        SEVERITY_CRITICAL,
        CONFIDENCE_HIGH
    ),
    "Slack Token": PatternConfig(
        re.compile(r"xox[baprs]-([0-9a-zA-Z]{10,48})"),
        SEVERITY_HIGH,
        CONFIDENCE_HIGH
    ),
    "Google API Key": PatternConfig(
        re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
        SEVERITY_HIGH,
        CONFIDENCE_HIGH
    ),
}

ENDPOINT_PATTERNS: Dict[str, Pattern] = {
    "Absolute URL": re.compile(r"https?://[a-zA-Z0-9\-\.]+(?:\:[0-9]+)?(?:/[a-zA-Z0-9_\-\.\?\&=\%/]*)?"),
    "WebSocket": re.compile(r"wss?://[a-zA-Z0-9\-\.]+(?:\:[0-9]+)?(?:/[a-zA-Z0-9_\-\.\?\&=\%/]*)?"),
    "Relative API Path": re.compile(r"[\"\'](\/(?:api|v[0-9]|graphql|auth|user|admin)[a-zA-Z0-9_\-\.\?\&=\%/]*)[\"\']"),
}
