import json
import time
import sys
from typing import List, Dict, Any, Optional
from .version import __version__
from .sarif import generate_sarif

class Colors:
    RESET = "\033[0m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    
    @staticmethod
    def colorize(text: str, color: str, no_color: bool = False) -> str:
        if no_color or not sys.stdout.isatty():
            return text
        return f"{color}{text}{Colors.RESET}"

class Reporter:
    def __init__(self, format_type: str, show_secrets: bool = False, redact_strategy: str = "partial", no_color: bool = False):
        self.format_type = format_type
        self.show_secrets = show_secrets
        # redaction: "none" (show), "partial", "full"
        self.redact_strategy = "none" if show_secrets else redact_strategy
        self.no_color = no_color
        self.start_time = time.time()

    def report(self, results: List[Dict[str, Any]], stats: Dict[str, Any]):
        if self.format_type == "json":
            self._print_json(results)
        elif self.format_type == "sarif":
            print(generate_sarif(results))
        elif self.format_type == "stats":
            self._print_stats(stats)
        else: # text
            self._print_text(results, stats)

    def mask_secret(self, value: str) -> str:
        if self.redact_strategy == "none":
            return value
        
        if self.redact_strategy == "full":
            return "*" * 16 # Fixed width for visual consistency or len(value)? Let's use 16
        
        # Partial
        if len(value) <= 8:
            return "*" * len(value)
        return value[:4] + "*" * (len(value) - 8) + value[-4:]

    def _print_json(self, results: List[Dict]):
        output = []
        for res in results:
            item = {
                "file": res.get("file"),
                "error": res.get("error"),
                "secrets": {},
                "endpoints": res.get("endpoints", {})
            }
            
            # Group rich matches
            matches = res.get("matches", [])
            if matches:
                grouped = {}
                for m in matches:
                    if m["type"] not in grouped:
                        grouped[m["type"]] = []
                    
                    val = m["value"]
                    val = self.mask_secret(val)
                        
                    grouped[m["type"]].append({
                        "value": val,
                        "severity": m["severity"],
                        "confidence": m["confidence"],
                        "line": m.get("line"),
                        "column": m.get("column")
                    })
                item["secrets"] = grouped
            
            output.append(item)
            
        print(json.dumps(output, indent=2))

    def _print_stats(self, stats: Dict[str, Any]):
        duration = time.time() - self.start_time
        print(json.dumps({
            "files_scanned": stats.get("files_scanned", 0),
            "secrets_found": stats.get("secrets_found", 0),
            "endpoints_found": stats.get("endpoints_found", 0),
            "execution_time_seconds": round(duration, 3)
        }, indent=2))

    def _print_text(self, results: List[Dict], stats: Dict):
        # Existing text formatting logic adapted
        for res in results:
            if res.get("error"):
                 print(Colors.colorize(f"[ERROR] {res['file']}: {res['error']}", Colors.RED, self.no_color))
                 continue

            matches = res.get("matches", [])
            endpoints = res.get("endpoints", {})

            if not matches and not endpoints:
                continue

            print()
            print(Colors.colorize(f"[FILE] {res['file']}", Colors.CYAN, self.no_color))
            
            if matches:
                print(Colors.colorize("  [!] Secrets:", Colors.YELLOW, self.no_color))
                grouped = {}
                for m in matches:
                    if m["type"] not in grouped:
                        grouped[m["type"]] = []
                    grouped[m["type"]].append(m)

                for secret_type, items in grouped.items():
                    # Pick severity/confidence from first item (usually same for type)
                    severity = items[0]["severity"]
                    confidence = items[0]["confidence"]
                    
                    sev_color = Colors.RED if severity in ["HIGH", "CRITICAL"] else Colors.YELLOW
                    header = f"    > {secret_type} [{severity} | {confidence}]:"
                    print(Colors.colorize(header, sev_color, self.no_color))
                    
                    for item in items:
                        val = item["value"]
                        val = self.mask_secret(val)
                        
                        loc = f"{item.get('line', '?')}:{item.get('column', '?')}"
                        print(f"      - {val} {Colors.colorize(f'({loc})', Colors.WHITE, self.no_color)}")
            
            if endpoints:
                print(Colors.colorize("  [*] Endpoints:", Colors.BLUE, self.no_color))
                for ep_type, values in endpoints.items():
                    print(f"    > {ep_type}:")
                    for v in values:
                         # v is just string in legacy dict.
                         # If we want context (is_auth), we need endpoint_matches.
                         # But 'endpoints' dict is simple.
                         # Let's print simply for now.
                        print(f"      - {v}")

        print()
        print(Colors.colorize("="*40, Colors.BLUE, self.no_color))
        print(Colors.colorize(" SCAN SUMMARY", Colors.BLUE, self.no_color))
        print(Colors.colorize("="*40, Colors.BLUE, self.no_color))
        print(f"Files Scanned: {stats.get('files_scanned', 0)}")
        print(f"Secrets Found: {stats.get('secrets_found', 0)}")
        
        # Breakdown
        if stats.get("secrets_by_severity"):
            for sev, count in stats["secrets_by_severity"].items():
                print(f"  {sev}: {count}")
