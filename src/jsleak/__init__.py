"""jsleak - A professional scanner for detecting secrets and endpoints in JavaScript files."""

__version__ = "0.5.11"

from .scanner import scan_content, ScanResult
from .fetcher import get_content

__all__ = ["scan_content", "ScanResult", "get_content", "__version__"]
