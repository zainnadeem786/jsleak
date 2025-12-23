import urllib.request
import urllib.error
import os
from typing import Union

class FetcherError(Exception):
    """Base exception for fetching errors."""
    pass

def get_content(source: str) -> str:
    """
    Retrieves content from a local file or a remote URL.

    Args:
        source: A local file path or a URL starting with http:// or https://.

    Returns:
        The content of the file or URL as a string.

    Raises:
        FetcherError: If the content cannot be retrieved or decoded.
    """
    if source.startswith("http://") or source.startswith("https://"):
        return _fetch_url(source)
    else:
        return _read_file(source)

def _read_file(path: str) -> str:
    if not os.path.exists(path):
        raise FetcherError(f"File not found: {path}")
    if not os.path.isfile(path):
        raise FetcherError(f"Path is not a file: {path}")
    
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except UnicodeDecodeError:
        # Fallback for non-utf8 files, though scanning binary might not be useful
        # We try latin-1 as a safe fallback
        with open(path, "r", encoding="latin-1") as f:
            return f.read()
    except OSError as e:
        raise FetcherError(f"Error reading file {path}: {e}")

def _fetch_url(url: str) -> str:
    req = urllib.request.Request(
        url, 
        headers={"User-Agent": "jsleak-scanner/0.1.0"}
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            charset = response.info().get_param('charset') or 'utf-8'
            content = response.read()
            return content.decode(charset, errors='replace')
    except (urllib.error.URLError, urllib.error.HTTPError) as e:
        raise FetcherError(f"Network error fetching {url}: {e}")
    except Exception as e:
        raise FetcherError(f"Unexpected error fetching {url}: {e}")
