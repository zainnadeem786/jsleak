import argparse
import sys
import json
import os
import time
from typing import List, Dict, Any
from .fetcher import get_content, FetcherError
from .scanner import scan_content
from .pattern_utils import get_severity, get_default_confidence
from .directory import scan_directory
from .ignorer import Ignorer
from .config import load_config
from .version import __version__
from .reporter import Reporter, Colors
from .baseline_manager import BaselineManager

def main():
    parser = argparse.ArgumentParser(
        description="jsleak: A professional scanner for exposing secrets and endpoints in JavaScript files.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  jsleak ./src -r
  jsleak ./src --format sarif > results.sarif
  jsleak https://example.com/app.js --show-secrets
  jsleak ./src --stats-only
  jsleak ./src --baseline baseline.json
"""
    )

    # Global Options
    parser.add_argument(
        "--version",
        action="store_true",
        help="Show jsleak version and exit."
    )
    parser.add_argument(
        "target",
        nargs="?",
        help="Path to a local file, directory, or a URL (http/https) to scan."
    )
    
    # Scan Options
    scan_group = parser.add_argument_group("Scan Options")
    scan_group.add_argument(
        "--recursive", "-r",
        action="store_true",
        help="Recursively scan directories."
    )
    scan_group.add_argument(
        "--config",
        help="Path to configuration file (default: .jsleak.yml)",
        default=".jsleak.yml"
    )
    scan_group.add_argument(
        "--baseline",
        help="Path to baseline JSON file to ignore known findings."
    )
    scan_group.add_argument(
        "--fail-on-severity",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        help="Override config failure threshold."
    )

    # Output Options
    output_group = parser.add_argument_group("Output Options")
    output_group.add_argument(
        "--format",
        choices=["text", "json", "sarif"],
        help="Output format (default: text)."
    )
    output_group.add_argument(
        "--stats-only",
        action="store_true",
        help="Show only execution statistics."
    )
    output_group.add_argument(
        "--hide-endpoints",
        action="store_true",
        help="Suppress endpoint output."
    )
    output_group.add_argument(
        "--verbose",
        action="store_true",
        help="Print additional metadata for debugging."
    )

    # Masking Options
    mask_group = parser.add_argument_group("Masking & Redaction")
    mask_group.add_argument(
        "--show-secrets",
        action="store_true",
        help="Show full secret values (overrides masking)."
    )
    mask_group.add_argument(
        "--mask",
        dest="mask",
        action="store_true",
        default=True,
        help="Force masked output (default)."
    )
    mask_group.add_argument(
        "--no-mask",
        dest="mask",
        action="store_false",
        help="Disable masking (same as --show-secrets)."
    )
    mask_group.add_argument(
        "--redact",
        choices=["partial", "full"],
        help="Redaction strategy (overrides config)."
    )
    
    args = parser.parse_args()
    
    # Version Command
    if args.version:
        print(f"jsleak v{__version__}")
        print(f"Python {sys.version.split()[0]}")
        sys.exit(0)

    # Validate Target
    if not args.target:
        parser.print_help()
        sys.exit(0)
    
    # Load Config
    config = load_config(args.config)

    # Determine Format
    format_type = args.format if args.format else "text"
    if args.stats_only:
        format_type = "stats"
    
    # Redaction Logic
    # CLI flags interactive logic
    # --show-secrets OR --no-mask -> "none"
    # --redact -> explicit strategy
    # Config -> fallback
    
    redact_strategy = config.redact_secrets
    if args.redact:
        redact_strategy = args.redact
    
    if args.show_secrets or not args.mask:
        redact_strategy = "none"
        
    # Baseline Manager
    baseline_path = args.baseline if args.baseline else config.baseline_path
    baseline_mgr = BaselineManager(baseline_path)

    # Reporter
    reporter = Reporter(
        format_type=format_type, 
        show_secrets=(redact_strategy == "none"),
        redact_strategy=redact_strategy,
        no_color=bool(os.getenv("NO_COLOR") or os.getenv("CI")) # Explicit no_color arg logic if needed
    )

    # Banner (Text mode only)
    if format_type == "text" and not args.stats_only and not args.verbose:
        # Standard Clean Header
        banner_color = Colors.BLUE
        print(Colors.colorize("+" + "-"*40 + "+", banner_color))
        print(Colors.colorize(f"| jsleak v{__version__:<31}|", banner_color))
        print(Colors.colorize(f"| scanning: {args.target:<29}|", banner_color))
        print(Colors.colorize("+" + "-"*40 + "+", banner_color))

    # Initialize Ignorer
    ignore_path = ".jsleakignore" 
    ignorer = Ignorer(ignore_path)

    # Scan
    is_url = args.target.startswith("http://") or args.target.startswith("https://")
    results = [] 
    
    stats = {
        "files_scanned": 0,
        "secrets_found": 0,
        "endpoints_found": 0,
        "secrets_by_severity": {}
    }

    def process_result(res):
        stats["files_scanned"] += 1
        
        # Filter Matches using Baseline and Config
        matches = res.get("matches", [])
        filtered_matches = []
        for m in matches:
             # Config Excludes
             if m["type"] in config.exclude_secrets:
                 continue
             
             # Baseline Check
             if baseline_mgr.should_ignore(m, res["file"]):
                 continue

             filtered_matches.append(m)
             
             # Stats
             stats["secrets_found"] += 1
             sev = m["severity"]
             stats["secrets_by_severity"][sev] = stats["secrets_by_severity"].get(sev, 0) + 1

        res["matches"] = filtered_matches
        
        # Endpoints
        eps = res.get("endpoints", {})
        count_eps = sum(len(v) for v in eps.values())
        stats["endpoints_found"] += count_eps
        
        if args.hide_endpoints:
            res["endpoints"] = {}
            
        results.append(res)
        
        if args.verbose:
             if res.get("error"):
                 print(f"DEBUG: Scanned {res['file']} - ERROR: {res['error']}", file=sys.stderr)
             else:
                 print(f"DEBUG: Scanned {res['file']} - Found {len(filtered_matches)} secrets", file=sys.stderr)

    try:
        if is_url:
            try:
                content = get_content(args.target)
                scan_res = scan_content(content)
                
                # Convert matches to dicts
                matches = []
                for m in scan_res.matches:
                     if not ignorer.should_ignore_secret(m.type):
                         matches.append(m.to_dict())

                res = {
                    "file": args.target,
                    "matches": matches,
                    "endpoints": scan_res.endpoints,
                    "error": None
                }
                process_result(res)
                
            except Exception as e:
                err_msg = str(e)
                if format_type == "json" or format_type == "sarif":
                   results.append({"file": args.target, "error": err_msg, "matches": [], "endpoints": {}})
                else:
                    print(Colors.colorize(f"ERROR: {err_msg}", Colors.RED), file=sys.stderr)
                    sys.exit(3) # Critical error for single target
        else:
            if not os.path.exists(args.target):
                 err_msg = f"Path not found: {args.target}"
                 if format_type == "json":
                    results.append({"file": args.target, "error": err_msg, "matches": [], "endpoints": {}})
                    print(json.dumps(results, indent=2))
                 else:
                    print(Colors.colorize(f"ERROR: {err_msg}", Colors.RED), file=sys.stderr)
                 sys.exit(3)

            for res in scan_directory(args.target, args.recursive, ignorer):
                 process_result(res)

        # Report
        reporter.report(results, stats)

        # Exit code logic
        # 0 -> no secrets above threshold
        # 1 -> secrets found below fail threshold
        # 2 -> secrets found meeting or exceeding fail threshold
        
        has_secrets = any(r.get("matches") for r in results)
        has_errors = any(r.get("error") for r in results)
        
        exit_code = 0
        
        # Determine failure threshold
        # CLI Flag > Config > Default (None)
        fail_sev = args.fail_on_severity if args.fail_on_severity else config.fail_on_severity
        
        if has_secrets:
            if fail_sev:
                severity_map = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
                threshold_val = severity_map.get(fail_sev, 100)
                
                should_fail = False
                for r in results:
                    for m in r.get("matches", []):
                        sev_val = severity_map.get(m["severity"], 0)
                        if sev_val >= threshold_val:
                            should_fail = True
                            break
                    if should_fail:
                        break
                
                if should_fail:
                    exit_code = 2 # Exceeds threshold
                else:
                    exit_code = 1 # Found, but below threshold
            else:
                # No threshold defined. 
                # "0 -> no secrets above threshold" implies if no threshold, are there secrets "above" it? 
                # If no threshold is set, technically no secrets are "above" the threshold (infinity). 
                # So maybe 1? 
                # User spec: "1 -> secrets below fail threshold". If threshold is None/Infinity, all secrets are below.
                # So 1 is correct for finding secrets without a fail block.
                exit_code = 1
        
        if has_errors and len(results) == 1: 
            # If single file scan failed and it was the only target
            exit_code = 3
            
        sys.exit(exit_code)

    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as e:
        print(f"CRITICAL ERROR: {e}", file=sys.stderr)
        sys.exit(3)

if __name__ == "__main__":
    main()
