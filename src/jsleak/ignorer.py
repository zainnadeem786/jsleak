from typing import List, Optional
import os

class Ignorer:
    """
    Handles exclusion logic based on .jsleakignore file.
    """
    def __init__(self, ignore_file_path: Optional[str] = None):
        self.ignored_paths: List[str] = []
        self.ignored_secrets: List[str] = []
        
        if ignore_file_path and os.path.exists(ignore_file_path):
            self._load_rules(ignore_file_path)

    def _load_rules(self, path: str):
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    
                    # If the line exactly matches a known secret type (heuristically)
                    # We might need a list of known secret types to be perfect, 
                    # but for now we treat any line without path separators as potential secret type?
                    # Or just simple logic: user provides strings.
                    # As per instructions: "Ignore rules may include: Secret types... or File names or paths"
                    
                    # We will match exact secret type name OR filename substring.
                    # Since we don't have the scanner imported here to avoid circular dep, 
                    # we will just store all rules and check against both.
                    # BUT distinguishing is helpful.
                    # Let's assume if it contains / or \ or . it is a path, else it *might* be a secret type.
                    # But "Generic API Key" has spaces.
                    
                    self.ignored_paths.append(line)
        except Exception:
            pass # Gracefully handle read errors

    def should_ignore_file(self, file_path: str) -> bool:
        """
        Check if the file path should be ignored.
        """
        # Normalize path for comparison
        norm_path = file_path.replace("\\", "/")
        
        for rule in self.ignored_paths:
            # Simple substring match for paths for now, or startswith/endswith?
            # User said "File names or paths".
            # If rule is "bootstrap.min.js", it should match "assets/bootstrap.min.js"
            # If rule is "vendor/", it should match "src/vendor/lib.js"
            
            # If rule looks like a secret type (e.g. "AWS Access Key"), we shouldn't match it against file path roughly
            # But the user might name a file "AWS Access Key". Unlikely.
            
            # We'll do a simple check: if rule is in norm_path.
            if rule in norm_path:
                return True
        return False

    def should_ignore_secret(self, secret_type: str) -> bool:
        """
        Check if the secret type should be ignored.
        """
        return secret_type in self.ignored_paths
