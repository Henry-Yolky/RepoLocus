"""Network-location checks used by privacy and HTTP boundaries."""

from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit


def is_loopback_url(url: str) -> bool:
    """Return whether an absolute HTTP URL targets this host's loopback interface."""

    try:
        parsed = urlsplit(url)
        hostname = (parsed.hostname or "").rstrip(".").casefold()
    except ValueError:
        return False
    if parsed.scheme not in {"http", "https"} or not hostname:
        return False
    if hostname == "localhost" or hostname.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False
