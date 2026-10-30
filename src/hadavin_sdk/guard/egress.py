"""Outbound allowlist: every host the core calls must be listed in ``egress.yaml``."""

from __future__ import annotations

from urllib.parse import urlsplit


class EgressRefused(PermissionError):
    pass


def egress_check(host_or_url: str, allowed: frozenset[str]) -> str:
    host = urlsplit(host_or_url).hostname if "://" in host_or_url else host_or_url
    host = (host or "").lower().rstrip(".")
    if not host or host not in allowed:
        raise EgressRefused(f"host not in egress.yaml: {host or '?'}")
    return host
