"""URL normalization and SSRF protection for scan targets."""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlsplit, urlunsplit

ALLOWED_SCHEMES = {"http", "https"}


class UrlRejectedError(ValueError):
    pass


def normalize_url(raw: str) -> str:
    """Canonical form: lowercase scheme/host, no fragment, no default port."""
    try:
        parts = urlsplit(raw.strip())
    except ValueError as exc:
        raise UrlRejectedError(f"unparseable URL: {raw!r}") from exc
    if not parts.scheme or not parts.hostname:
        raise UrlRejectedError(f"url must be absolute with host: {raw!r}")
    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise UrlRejectedError(f"scheme {scheme!r} not allowed")
    host = (parts.hostname or "").lower()
    port = parts.port
    default = {"http": 80, "https": 443}.get(scheme)
    netloc = host if port in (None, default) else f"{host}:{port}"
    path = parts.path or "/"
    return urlunsplit((scheme, netloc, path, parts.query, ""))


def _is_private_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    private_sets = [
        ip.is_private, ip.is_loopback, ip.is_link_local,
        ip.is_multicast, ip.is_reserved, ip.is_unspecified,
    ]
    return any(private_sets)


def assert_public_url(raw: str) -> str:
    """Normalize + reject non-public targets (SSRF guard).

    Resolves the hostname and checks every resolved address; also rejects
    literal private IPs. Raises UrlRejectedError.
    """
    normalized = normalize_url(raw)
    parts = urlsplit(normalized)
    host = parts.hostname or ""
    try:
        addr_infos = socket.getaddrinfo(host, None)
        resolved = {info[4][0] for info in addr_infos}
    except socket.gaierror as exc:
        raise UrlRejectedError(f"cannot resolve host: {host!r}") from exc
    for ip_str in resolved:
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if _is_private_ip(ip):
            raise UrlRejectedError(
                f"target resolves to private/reserved address ({ip_str})"
            )
    return normalized


def safe_target_url(raw: str, guard_disabled: bool = False) -> str:
    """normalize_url + optional SSRF guard."""
    if guard_disabled:
        return normalize_url(raw)
    return assert_public_url(raw)
