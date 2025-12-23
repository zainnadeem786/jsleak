import math
from typing import Dict, List, Set, NamedTuple, Optional, Any
from dataclasses import dataclass
from .patterns import SECRETS_PATTERNS, ENDPOINT_PATTERNS, CONFIDENCE_HIGH, CONFIDENCE_MEDIUM, CONFIDENCE_LOW

@dataclass
class Location:
    line: int
    column: int
    index: int

@dataclass
class SecretMatch:
    type: str
    value: str
    severity: str
    confidence: str
    location: Location

    def to_dict(self):
        return {
            "type": self.type,
            "value": self.value,
            "severity": self.severity,
            "confidence": self.confidence,
            "line": self.location.line,
            "column": self.location.column,
            "index": self.location.index
        }

@dataclass
class EndpointMatch:
    type: str
    value: str
    location: Location
    is_auth: bool = False

    def to_dict(self):
        return {
            "type": self.type,
            "value": self.value,
            "line": self.location.line,
            "column": self.location.column,
            "is_auth": self.is_auth
        }

class ScanResult(NamedTuple):
    secrets: Dict[str, List[str]] # Legacy
    endpoints: Dict[str, List[str]] # Legacy
    matches: List[SecretMatch] 
    endpoint_matches: List[EndpointMatch]

class Scanner:
    """
    Scans text content for defined patterns of secrets and endpoints.
    """

    def scan(self, content: str) -> ScanResult:
        """
        Scans the provided content string for secrets and endpoints.
        """
        matches = self._scan_secrets_rich(content)
        endpoint_matches = self._scan_endpoints_rich(content)
        
        # Backwards compatibility
        secrets_dict = {}
        for m in matches:
            if m.type not in secrets_dict:
                secrets_dict[m.type] = []
            secrets_dict[m.type].append(m.value)
        
        endpoints_dict = {}
        for m in endpoint_matches:
            if m.type not in endpoints_dict:
                endpoints_dict[m.type] = set()
            endpoints_dict[m.type].add(m.value)
            
        endpoints_desc = {k: sorted(list(v)) for k, v in endpoints_dict.items()}

        # Sort dicts
        for k in secrets_dict:
            secrets_dict[k].sort()

        return ScanResult(
            secrets=secrets_dict, 
            endpoints=endpoints_desc, 
            matches=matches,
            endpoint_matches=endpoint_matches
        )

    def _get_location(self, content: str, start_index: int) -> Location:
        # Calculate line and column
        # This can be slow for very large files if done repeatedly.
        # But for typical JS files it's fine.
        line = content.count('\n', 0, start_index) + 1
        last_newline = content.rfind('\n', 0, start_index)
        if last_newline == -1:
            column = start_index + 1
        else:
            column = start_index - last_newline
        
        return Location(line=line, column=column, index=start_index)

    def _scan_secrets_rich(self, content: str) -> List[SecretMatch]:
        matches_found = []

        for name, config in SECRETS_PATTERNS.items():
            pattern = config.pattern
            # Use finditer for location info
            for match in pattern.finditer(content):
                candidate = self._extract_match_text(match)
                if candidate:
                    confidence = self._calculate_confidence(name, candidate, config.confidence)
                    if self._validate_secret(name, candidate, confidence):
                        loc = self._get_location(content, match.start())
                        matches_found.append(SecretMatch(
                            type=name,
                            value=candidate,
                            severity=config.severity,
                            confidence=confidence,
                            location=loc
                        ))
        
        return matches_found

    def _scan_endpoints_rich(self, content: str) -> List[EndpointMatch]:
        results = []
        auth_keywords = ["login", "signin", "auth", "token", "password", "credential"]

        for name, pattern in ENDPOINT_PATTERNS.items():
            for match in pattern.finditer(content):
                candidate = self._extract_match_text(match)
                if candidate:
                   loc = self._get_location(content, match.start())
                   
                   # Check for auth context in the value itself
                   is_auth = any(k in candidate.lower() for k in auth_keywords)
                   
                   results.append(EndpointMatch(
                       type=name,
                       value=candidate,
                       location=loc,
                       is_auth=is_auth
                   ))
        
        return results

    def _extract_match_text(self, match) -> str:
        # Regex match object
        # If groups present, take first group, else take full match
        if match.groups():
            return next((g for g in match.groups() if g is not None), "")
        return match.group(0)

    def _extract_match(self, match) -> str:
        # Legacy support for internal method if needed, but we moved to `_extract_match_text` with regex match obj
        if isinstance(match, tuple):
             return next((m for m in match if m), "")
        return match

    def _calculate_confidence(self, name: str, value: str, default_confidence: str) -> str:
        confidence = default_confidence
        if name == "Generic API Key":
            entropy_score = self._get_entropy(value)
            if entropy_score > 4.0:
                confidence = CONFIDENCE_HIGH
            elif entropy_score > 3.5:
                confidence = CONFIDENCE_MEDIUM
            else:
                confidence = CONFIDENCE_LOW
        return confidence

    def _validate_secret(self, name: str, value: str, confidence: str) -> bool:
        if name == "Generic API Key":
             return self._get_entropy(value) > 3.0
        return True

    def _get_entropy(self, value: str) -> float:
        if not value:
            return 0.0
        prob = [float(value.count(c)) / len(value) for c in dict.fromkeys(list(value))]
        return -sum([p * math.log(p) / math.log(2.0) for p in prob])

def scan_content(content: str) -> ScanResult:
    scanner = Scanner()
    return scanner.scan(content)
