# jsleak CLI Testing Guide

## Quick Reference: All Available Flags

### 1. Version & Help
```bash
# Show version
python -m jsleak.cli --version

# Show help with all options
python -m jsleak.cli --help
```

### 2. Basic Scanning
```bash
# Scan single file
python -m jsleak.cli dummy_data/secrets.js

# Scan directory recursively
python -m jsleak.cli dummy_data -r

# Scan URL
python -m jsleak.cli https://example.com/app.js
```

### 3. Output Formats
```bash
# Text output (default)
python -m jsleak.cli dummy_data/secrets.js

# JSON output
python -m jsleak.cli dummy_data/secrets.js --format json

# SARIF output
python -m jsleak.cli dummy_data/secrets.js --format sarif

# Stats only
python -m jsleak.cli dummy_data -r --stats-only
```

### 4. Masking & Redaction
```bash
# Default partial masking (AKIA****1234)
python -m jsleak.cli dummy_data/secrets.js

# Full masking (****************)
python -m jsleak.cli dummy_data/secrets.js --redact full

# Show full secrets
python -m jsleak.cli dummy_data/secrets.js --show-secrets

# Alternative: --no-mask
python -m jsleak.cli dummy_data/secrets.js --no-mask
```

### 5. Baseline Support
```bash
# Create a baseline (first, get findings as JSON)
python -m jsleak.cli dummy_data -r --format json > findings.json

# Then create baseline manually or use findings to generate baseline.json
# Example baseline.json:
# {
#   "ignored_findings": [
#     "hash1",
#     "hash2"
#   ]
# }

# Scan with baseline
python -m jsleak.cli dummy_data -r --baseline baseline.json
```

### 6. Configuration File
```bash
# Use custom config
python -m jsleak.cli dummy_data -r --config my-config.yml

# Default config (.jsleak.yml) is auto-loaded if present
```

### 7. Failure Thresholds
```bash
# Fail only on HIGH or CRITICAL
python -m jsleak.cli dummy_data -r --fail-on-severity HIGH
echo $LASTEXITCODE  # Check exit code (PowerShell)

# Fail on MEDIUM or above
python -m jsleak.cli dummy_data -r --fail-on-severity MEDIUM
```

### 8. Debugging & Verbose
```bash
# Verbose mode (shows per-file debug info)
python -m jsleak.cli dummy_data -r --verbose

# Hide endpoints
python -m jsleak.cli dummy_data -r --hide-endpoints
```

## Exit Codes

- `0` → No secrets above threshold (clean scan)
- `1` → Secrets found below fail threshold
- `2` → Secrets found meeting/exceeding fail threshold
- `3` → Critical error (file not found, network error)
- `130` → Keyboard interrupt (Ctrl+C)

### Testing Exit Codes
```bash
# Test exit code 0 (no secrets or below threshold)
python -m jsleak.cli dummy_data/endpoints.js
echo $LASTEXITCODE

# Test exit code 1 (secrets found, no threshold)
python -m jsleak.cli dummy_data/secrets.js
echo $LASTEXITCODE

# Test exit code 2 (secrets exceed threshold)
python -m jsleak.cli dummy_data/secrets.js --fail-on-severity LOW
echo $LASTEXITCODE

# Test exit code 3 (file not found)
python -m jsleak.cli nonexistent.js
echo $LASTEXITCODE
```

## Combined Examples

### Enterprise CI Pipeline
```bash
# Production scan with baseline and strict threshold
python -m jsleak.cli ./src -r \
  --baseline baseline.json \
  --fail-on-severity HIGH \
  --format sarif > results.sarif
```

### Security Audit
```bash
# Full audit with all secrets visible
python -m jsleak.cli ./src -r \
  --show-secrets \
  --format json > audit.json
```

### Quick Stats Check
```bash
# Fast overview
python -m jsleak.cli ./src -r --stats-only
```

### Debug Scan
```bash
# Verbose output for troubleshooting
python -m jsleak.cli ./src -r --verbose
```

## Testing Checklist

- [ ] `--version` shows correct version
- [ ] `--help` displays all options
- [ ] Basic scan works on file
- [ ] Recursive scan works on directory
- [ ] JSON output is valid
- [ ] SARIF output is valid
- [ ] Stats mode shows summary
- [ ] `--show-secrets` reveals full values
- [ ] `--redact full` masks completely
- [ ] `--redact partial` masks partially (default)
- [ ] `--verbose` shows debug info
- [ ] `--hide-endpoints` suppresses endpoints
- [ ] `--fail-on-severity` changes exit code
- [ ] Exit code 0 for clean scan
- [ ] Exit code 1 for secrets below threshold
- [ ] Exit code 2 for secrets above threshold
- [ ] Exit code 3 for errors
- [ ] Baseline suppresses known findings
- [ ] Config file is loaded correctly
