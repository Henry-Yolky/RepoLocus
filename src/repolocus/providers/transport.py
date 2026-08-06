"""Explicit, previewable HTTP transport policy for model providers."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Literal
from urllib.parse import quote, unquote, urlsplit

from repolocus.security.network import is_loopback_url
from repolocus.security.privacy import canonical_endpoint

if TYPE_CHECKING:
    from repolocus.config import Settings

ProxyMode = Literal["disabled", "environment", "explicit"]


@dataclass(frozen=True, slots=True)
class ProviderTransport:
    """One exact direct/proxy route, safe to bind to preview and consent."""

    policy: ProxyMode
    mode: Literal["direct", "proxy"]
    identity: str
    proxy: str | None = None
    proxy_url: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if self.policy not in {"disabled", "environment", "explicit"}:
            raise ValueError("transport policy is invalid")
        if self.mode not in {"direct", "proxy"}:
            raise ValueError("transport mode is invalid")
        if len(self.identity) != 64:
            raise ValueError("transport identity must be a SHA-256 digest")
        try:
            bytes.fromhex(self.identity)
        except ValueError as exc:
            raise ValueError("transport identity must be a SHA-256 digest") from exc
        if self.mode == "direct" and (self.proxy is not None or self.proxy_url is not None):
            raise ValueError("direct transport cannot carry a proxy route")
        if self.mode == "proxy" and (not self.proxy or not self.proxy_url):
            raise ValueError("proxy transport requires an exact proxy route")

    def preview(self) -> dict[str, str]:
        data = {"mode": self.mode, "policy": self.policy}
        if self.proxy is not None:
            data["proxy"] = self.proxy
        return data


def _route_identity(policy: ProxyMode, mode: str, proxy_url: str | None) -> str:
    payload = json.dumps(
        {"mode": mode, "policy": policy, "proxy": proxy_url},
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def direct_transport(policy: ProxyMode = "disabled") -> ProviderTransport:
    return ProviderTransport(policy, "direct", _route_identity(policy, "direct", None))


def _canonical_proxy_url(value: str) -> tuple[str, str]:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("proxy URL must be a non-empty URL")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise ValueError("proxy URL must not contain control characters")
    stripped = value.strip()
    try:
        parsed = urlsplit(stripped)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("proxy URL contains an invalid port") from exc
    scheme = parsed.scheme.casefold()
    if scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("proxy URL must be an absolute http(s) URL")
    if parsed.query or parsed.fragment or parsed.path not in {"", "/"}:
        raise ValueError("proxy URL must not contain a path, query, or fragment")
    host = parsed.hostname.rstrip(".").casefold()
    if not host:
        raise ValueError("proxy URL contains an invalid hostname")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ValueError("proxy URL contains an invalid hostname") from exc
        rendered_host = host
    else:
        rendered_host = f"[{address.compressed}]" if address.version == 6 else address.compressed
    effective_port = port if port is not None else (443 if scheme == "https" else 80)
    display = f"{scheme}://{rendered_host}:{effective_port}"
    userinfo = ""
    if parsed.username is not None:
        userinfo = quote(unquote(parsed.username), safe="")
        if parsed.password is not None:
            userinfo += ":" + quote(unquote(parsed.password), safe="")
        userinfo += "@"
    canonical = f"{scheme}://{userinfo}{rendered_host}:{effective_port}"
    return canonical, display


def proxy_transport(policy: ProxyMode, proxy_url: str) -> ProviderTransport:
    canonical, display = _canonical_proxy_url(proxy_url)
    return ProviderTransport(
        policy,
        "proxy",
        # Consent is bound to the credential-free transport route. Hashing
        # userinfo would still persist a verifier for weak proxy credentials
        # and would unnecessarily invalidate consent when credentials rotate.
        _route_identity(policy, "proxy", display),
        proxy=display,
        proxy_url=canonical,
    )


def _environment_value(environ: Mapping[str, str], name: str) -> str:
    for key in (name.casefold(), name.upper()):
        value = environ.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _no_proxy_match(endpoint: str, environ: Mapping[str, str]) -> bool:
    raw = _environment_value(environ, "no_proxy")
    if not raw:
        return False
    parsed = urlsplit(endpoint)
    host = (parsed.hostname or "").rstrip(".").casefold()
    effective_port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    for item in raw.split(","):
        candidate = item.strip()
        if not candidate:
            continue
        if candidate == "*":
            return True
        if "://" in candidate:
            candidate = urlsplit(candidate).netloc
        candidate_host = candidate
        candidate_port: int | None = None
        if candidate.startswith("[") and "]" in candidate:
            closing = candidate.index("]")
            candidate_host = candidate[1:closing]
            if candidate[closing + 1 :].startswith(":"):
                with _ignored_value_error():
                    candidate_port = int(candidate[closing + 2 :])
        elif candidate.count(":") == 1:
            possible_host, possible_port = candidate.rsplit(":", 1)
            with _ignored_value_error():
                candidate_port = int(possible_port)
                candidate_host = possible_host
        if candidate_port is not None and candidate_port != effective_port:
            continue
        candidate_host = candidate_host.strip().rstrip(".").casefold()
        try:
            network = ipaddress.ip_network(candidate_host, strict=False)
        except ValueError:
            normalized = candidate_host.removeprefix("*.").removeprefix(".")
            if host == normalized or host.endswith("." + normalized):
                return True
        else:
            if address is not None and address in network:
                return True
    return False


class _ignored_value_error:
    def __enter__(self) -> None:
        return None

    def __exit__(self, exception_type, exception, traceback) -> bool:  # type: ignore[no-untyped-def]
        return exception_type is ValueError


def build_provider_transport(
    settings: Settings,
    endpoint: str,
    *,
    environ: Mapping[str, str] | None = None,
) -> ProviderTransport:
    """Resolve the exact route once; callers reuse it after consent approval."""

    canonical_endpoint(endpoint)
    policy = settings.proxy_mode
    if policy not in {"disabled", "environment", "explicit"}:
        raise ValueError("proxy_mode must be disabled, environment, or explicit")
    if is_loopback_url(endpoint):
        return direct_transport(policy)
    if policy == "disabled":
        return direct_transport("disabled")
    if policy == "explicit":
        return proxy_transport("explicit", settings.proxy_url)
    environment = os.environ if environ is None else environ
    if _no_proxy_match(endpoint, environment):
        return direct_transport("environment")
    scheme = urlsplit(endpoint).scheme.casefold()
    proxy_url = _environment_value(environment, f"{scheme}_proxy")
    if not proxy_url:
        proxy_url = _environment_value(environment, "all_proxy")
    if not proxy_url:
        return direct_transport("environment")
    return proxy_transport("environment", proxy_url)
