import json
import hashlib
from typing import Set, Dict, List, Any, Optional
import os

class BaselineManager:
    def __init__(self, baseline_path: Optional[str]):
        self.baseline_path = baseline_path
        self.signatures: Set[str] = set()
        if self.baseline_path and os.path.exists(self.baseline_path):
            self._load_baseline()

    def _load_baseline(self):
        try:
            with open(self.baseline_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                # Baseline format: List of finding objects or hashes.
                # Use a specific 'signatures' key or assuming list of hashes for simplicity.
                # Or standard SARIF based baseline? 
                # Let's support a simple JSON list of hashes string.
                # Or a specific format: { "ignored_findings": ["hash1", "hash2"] }
                if isinstance(data, dict):
                    self.signatures = set(data.get("ignored_findings", []))
                elif isinstance(data, list):
                    self.signatures = set(data)
        except Exception:
            pass # Fail silently or log? Silent for now.

    def generate_signature(self, match: Dict[str, Any], file_path: str) -> str:
        # Create a deterministic signature for a finding
        # Signature = hash(file_path_relative + type + value + line)
        # We include line to identify specific occurrence, but this breaks if code shifts.
        # Often it's better to hash (file + type + value) or (file + type + context).
        # Given we don't store context snippet, (file + type + value) is robust enough for identical secrets.
        # If the same secret appears multiple times in a file, all are ignored if one is. This is usually desired.
        
        # Normalize file path to relative if possible? 
        # Ideally baseline uses repo-relative paths. 
        # We'll use the provided path, assuming scanner uses consistent paths.
        
        key = f"{file_path}:{match['type']}:{match['value']}"
        return hashlib.sha256(key.encode('utf-8')).hexdigest()

    def should_ignore(self, match: Dict[str, Any], file_path: str) -> bool:
        sig = self.generate_signature(match, file_path)
        return sig in self.signatures

    def create_baseline_data(self, findings: List[Dict[str, Any]]) -> Dict[str, List[str]]:
        # Generates the baseline JSON structure from current findings
        sigs = set()
        for f in findings:
             # findings structure from directory scan: {file: path, matches: [...]}
             file_path = f["file"]
             for m in f.get("matches", []):
                 sigs.add(self.generate_signature(m, file_path))
        
        return {"ignored_findings": sorted(list(sigs))}
