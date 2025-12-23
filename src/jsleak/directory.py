import os
from typing import List, Dict, Generator, Any
from .scanner import scan_content, ScanResult
from .ignorer import Ignorer
from .fetcher import get_content, FetcherError

def scan_directory(
    path: str, 
    recursive: bool = False, 
    ignorer: Ignorer = None
) -> Generator[Dict[str, Any], None, None]:
    """
    Scans a directory for JavaScript files.
    """
    files_to_scan = []
    
    if os.path.isfile(path):
        files_to_scan.append(path)
    elif os.path.isdir(path):
        for root, dirs, files in os.walk(path):
            files.sort()
            dirs.sort()
            
            for file in files:
                if not (file.lower().endswith(".js") or file.lower().endswith(".mjs")):
                    continue
                if file.lower().endswith(".min.js"):
                    continue
                full_path = os.path.join(root, file)
                files_to_scan.append(full_path)
            
            if not recursive:
                break

    for file_path in files_to_scan:
        if ignorer and ignorer.should_ignore_file(file_path):
            continue
            
        try:
            content = get_content(file_path)
            result = scan_content(content)
            
            # Convert matches to dicts for yielding
            matches = [m.to_dict() for m in result.matches]

            # Filter secrets based on ignorer
            if ignorer and matches:
                filtered_matches = []
                for m in matches:
                    if not ignorer.should_ignore_secret(m["type"]):
                        filtered_matches.append(m)
                matches = filtered_matches
            
            # Reconstruct legacy secrets dict from filtered matches
            filtered_secrets = {}
            for m in matches:
                t = m["type"]
                if t not in filtered_secrets:
                    filtered_secrets[t] = []
                filtered_secrets[t].append(m["value"])
            for k in filtered_secrets:
                 filtered_secrets[k].sort()

            yield {
                "file": file_path,
                "matches": matches,
                "secrets": filtered_secrets,
                "endpoints": result.endpoints,
                "error": None
            }
            
        except Exception as e:
            yield {
                "file": file_path,
                "matches": [],
                "secrets": {},
                "endpoints": {},
                "error": str(e)
            }
