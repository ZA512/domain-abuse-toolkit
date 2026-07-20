from __future__ import annotations

import ipaddress
import re
import socket
from collections.abc import Callable, Iterable
from contextlib import suppress
from urllib.parse import SplitResult, urlsplit, urlunsplit

import tldextract

from domain_abuse_toolkit.models import NormalizedTarget

_CONTROL_OR_SPACE = re.compile(r"[\x00-\x20\x7f]")
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=False)
_ALLOWED_SCHEMES = {"http", "https"}
_ALLOWED_PORTS = {80, 443}


class TargetValidationError(ValueError):
    """Raised when a target is malformed or prohibited by collection policy."""


def _ascii_host(host: str) -> tuple[str, str]:
    unicode_host = host.rstrip(".").lower()
    if not unicode_host or _CONTROL_OR_SPACE.search(unicode_host):
        raise TargetValidationError("The target host is empty or contains prohibited characters.")
    if "%" in unicode_host:
        raise TargetValidationError("IPv6 zone identifiers are not allowed.")
    try:
        ascii_host = unicode_host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise TargetValidationError(
            "The target host is not a valid internationalized name."
        ) from exc
    return ascii_host, unicode_host


def _registrable_domain(host: str) -> str:
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        extracted = _EXTRACT(host)
        registrable = extracted.top_domain_under_public_suffix
        return registrable or host


def normalize_target(value: str) -> NormalizedTarget:
    exact = value.strip()
    if not exact or _CONTROL_OR_SPACE.search(exact):
        raise TargetValidationError(
            "The target is empty or contains whitespace/control characters."
        )
    if "\\" in exact:
        raise TargetValidationError("Backslashes are not allowed in target URLs.")

    candidate = exact if "://" in exact else f"https://{exact}"
    parsed: SplitResult = urlsplit(candidate)
    scheme = parsed.scheme.lower()
    if scheme not in _ALLOWED_SCHEMES:
        raise TargetValidationError("Only HTTP and HTTPS targets are allowed.")
    if parsed.username is not None or parsed.password is not None:
        raise TargetValidationError("Embedded URL credentials are not allowed.")
    if not parsed.hostname:
        raise TargetValidationError("The target URL does not contain a host.")

    ascii_host, unicode_host = _ascii_host(parsed.hostname)
    try:
        port = parsed.port
    except ValueError as exc:
        raise TargetValidationError("The target URL contains an invalid port.") from exc
    if port is not None and port not in _ALLOWED_PORTS:
        raise TargetValidationError("Only standard HTTP and HTTPS ports are allowed in the MVP.")

    is_ipv6 = False
    with suppress(ValueError):
        is_ipv6 = ipaddress.ip_address(ascii_host).version == 6

    display_host = f"[{ascii_host}]" if is_ipv6 else ascii_host
    netloc = f"{display_host}:{port}" if port is not None else display_host
    path = parsed.path or "/"
    normalized_url = urlunsplit((scheme, netloc, path, parsed.query, ""))

    return NormalizedTarget(
        exact_input=exact,
        normalized_url=normalized_url,
        scheme=scheme,
        host=ascii_host,
        unicode_host=unicode_host,
        registrable_domain=_registrable_domain(ascii_host),
        port=port,
        path=path,
        query=parsed.query,
    )


def is_public_address(value: str) -> bool:
    """Return True only for addresses safe to reach from a collection worker."""

    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return address.is_global


def validate_resolved_addresses(addresses: Iterable[str]) -> tuple[str, ...]:
    unique = tuple(dict.fromkeys(addresses))
    if not unique:
        raise TargetValidationError("The target did not resolve to an address.")
    prohibited = [address for address in unique if not is_public_address(address)]
    if prohibited:
        raise TargetValidationError(
            "The target resolves to a non-public or prohibited address: " + ", ".join(prohibited)
        )
    return unique


Resolver = Callable[[str, int | None], list[tuple]]


def resolve_public_target(
    target: NormalizedTarget,
    resolver: Resolver = socket.getaddrinfo,
) -> tuple[str, ...]:
    """Resolve and validate a target immediately before a network connection."""

    port = target.port or (443 if target.scheme == "https" else 80)
    try:
        answers = resolver(target.host, port)
    except OSError as exc:
        raise TargetValidationError("The target could not be resolved.") from exc
    addresses = [answer[4][0] for answer in answers]
    return validate_resolved_addresses(addresses)
