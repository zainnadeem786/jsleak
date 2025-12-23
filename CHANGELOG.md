# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.0] - 2025-12-23
### Added
- **Baseline Support**: Use `--baseline baseline.json` to process existing findings without triggering failure.
- **Improved Reporting**: New `Reporter` engine supports Stats mode (`--stats-only`), cleaner CLI output, and partial/full redaction keys.
- **Redaction Control**: Use `--redact full/partial` to control masking density.
- **Endpoint Intelligence**: Detects auth-related endpoints and adds context.
- **Execution Stats**: Get a quick summary of scan performance and findings.

## [0.4.0] - 2025-12-23
### Added
- **Accurate Locations**: Reports line and column numbers for secrets and endpoints.
- **Enterprise SARIF**: Hardened SARIF output with validation, rule metadata, and correct severity mapping.
- **Configurable Exit Codes**: `fail_on_severity` in `.jsleak.yml` allows breaking builds on specific severity levels.
- **Version Tracking**: Helper shows correct version in CLI and reports.
- **Location in output**: CLI now shows `(line:col)` next to findings.

## [0.3.0] - 2025-12-23
### Added
- **Confidence Scoring**: Secrets now include HIGH/MEDIUM/LOW confidence based on entropy and context.
- **Secret Masking**: Secrets are masked by default (`AKIA****...`). Use `--show-secrets` to reveal.
- **Configuration File**: Support for `.jsleak.yml` to configure excludes and thresholds.
- **SARIF Output**: Added `--format sarif` for integration with GitHub Security and CI tools.
- **CLI Improvements**: Enhanced colors and status reporting; auto-disable color in CI.

### Changed
- CLI output format improved for readability.
- `ScanResult` internal structure now includes rich `matches`.

## [0.2.0] - 2025-12-23
### Added
- Directory scanning support (`-r` flag).
- `.jsleakignore` support.
- File-level grouping in output.

## [0.1.1] - 2025-12-23
### Added
- JSON output format.
- Severity levels (CRITICAL, HIGH, MEDIUM).
- Entropy checks for false-positive reduction.

## [0.1.0] - 2025-12-23
### Added
- Initial release.
- Secret scanning (AWS, JWT, Keys).
- Endpoint extraction.
- CLI and Library API.
