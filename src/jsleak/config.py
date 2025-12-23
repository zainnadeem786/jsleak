from typing import NamedTuple, Dict, Any, Optional
import yaml
import os

class Config(NamedTuple):
    exclude_paths: list
    exclude_secrets: list
    confidence_threshold: str  # LOW, MEDIUM, HIGH
    fail_on_severity: Optional[str] # Trigger non-zero exit code if this severity or higher is found
    baseline_path: Optional[str] # Path to baseline JSON file
    redact_secrets: str # "partial" (default), "full", "none" (show-secrets)

DEFAULT_CONFIG = Config(
    exclude_paths=[],
    exclude_secrets=[],
    confidence_threshold="LOW",
    fail_on_severity=None,
    baseline_path=None,
    redact_secrets="partial"
)

def load_config(path: str = ".jsleak.yml") -> Config:
    if not os.path.exists(path):
        return DEFAULT_CONFIG
    
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
            
        return Config(
            exclude_paths=data.get("exclude", {}).get("paths", []),
            exclude_secrets=data.get("exclude", {}).get("secrets", []),
            confidence_threshold=data.get("confidence_threshold", "LOW"),
            fail_on_severity=data.get("fail_on_severity"),
            baseline_path=data.get("baseline_path"),
            redact_secrets=data.get("redact_secrets", "partial")
        )
    except Exception:
        return DEFAULT_CONFIG
