import json
from typing import List, Dict, Any, Optional
from .version import __version__

def generate_sarif(results: List[Dict[str, Any]]) -> str:
    """
    Generates a SARIF output string from the scan results.
    """
    
    rules_dict = {}
    results_sarif = []
    
    for res in results:
        file_uri = res["file"].replace("\\", "/") # normalize
        
        matches = res.get("matches", [])
        
        for match in matches:
            rule_id = match["type"].replace(" ", "-").lower()
            
            # Register Rule
            if rule_id not in rules_dict:
                rules_dict[rule_id] = {
                    "id": rule_id,
                    "name": match["type"],
                    "shortDescription": {"text": f"Detected {match['type']}"},
                    "defaultConfiguration": {
                        "level": _map_severity_to_level(match["severity"])
                    },
                    "properties": {
                         "params": {
                             "severity": match["severity"],
                             "confidence": match["confidence"]
                         }
                    }
                }
            
            # Create Result
            results_sarif.append({
                "ruleId": rule_id,
                "level": _map_severity_to_level(match["severity"]),
                "message": {"text": f"Found {match['type']} with {match['confidence']} confidence."},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": file_uri},
                        "region": {
                            "startLine": match.get("line", 1),
                            "startColumn": match.get("column", 1)
                        }
                    }
                }],
                "properties": {
                    "confidence": match["confidence"],
                    "severity": match["severity"]
                }
            })

    sarif_output = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "jsleak",
                    "version": __version__,
                    "rules": list(rules_dict.values())
                }
            },
            "results": results_sarif
        }]
    }
    
    return json.dumps(sarif_output, indent=2)

def _map_severity_to_level(severity: str) -> str:
    """
    Direct mapping of internal severity to SARIF 'level'.
    CRITICAL, HIGH -> error
    MEDIUM -> warning
    LOW -> note
    """
    if severity in ["CRITICAL", "HIGH"]: 
        return "error"
    if severity == "MEDIUM":
        return "warning"
    return "note"

