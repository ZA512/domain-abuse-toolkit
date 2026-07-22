from __future__ import annotations

import ipaddress
import json
import threading
import time
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote, urljoin

from domain_abuse_toolkit.models import (
    CollectorError,
    CollectorObservation,
    CollectorResult,
    CollectorStatus,
    NormalizedTarget,
)
from domain_abuse_toolkit.security.targets import TargetValidationError, normalize_target
from domain_abuse_toolkit.services.collectors import CollectorOutput
from domain_abuse_toolkit.services.evidence import PendingArtifact
from domain_abuse_toolkit.services.web_collector import (
    BoundedAddressResolver,
    DirectHttpClient,
    WebTransportError,
)

_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
_REDIRECT_STATUSES = {301, 302, 303, 307, 308}
_RDAP_ACCEPT = "application/rdap+json,application/json;q=0.9"


class RdapCollectionError(ValueError):
    def __init__(self, code: str, message: str, *, retryable: bool = False) -> None:
        super().__init__(message)
        self.code = code
        self.retryable = retryable


class RdapCollector:
    """Discover the authoritative RDAP service through IANA and capture public data."""

    version = "1.0"

    def __init__(
        self,
        *,
        address_resolver: BoundedAddressResolver | None = None,
        client: DirectHttpClient | None = None,
        connect_timeout_seconds: float = 5.0,
        read_timeout_seconds: float = 5.0,
        total_timeout_seconds: float = 30.0,
        max_redirects: int = 3,
        max_response_bytes: int = 1024 * 1024,
        bootstrap_cache_seconds: float = 24 * 60 * 60,
    ) -> None:
        self.address_resolver = address_resolver or BoundedAddressResolver()
        self.client = client or DirectHttpClient()
        self.connect_timeout_seconds = connect_timeout_seconds
        self.read_timeout_seconds = read_timeout_seconds
        self.total_timeout_seconds = total_timeout_seconds
        self.max_redirects = max_redirects
        self.max_response_bytes = max_response_bytes
        self.bootstrap_cache_seconds = bootstrap_cache_seconds
        self._cache_lock = threading.Lock()
        self._bootstrap_cache: tuple[float, bytes, dict[str, Any], str] | None = None

    def collect(self, target: NormalizedTarget, snapshot_id: str) -> CollectorOutput:
        started_at = datetime.now(UTC)
        deadline = time.monotonic() + self.total_timeout_seconds
        domain = target.registrable_domain
        artifacts: list[PendingArtifact] = []
        observations: list[CollectorObservation] = []
        errors: list[CollectorError] = []
        try:
            bootstrap_bytes, bootstrap, bootstrap_source = self._bootstrap(deadline)
            base_url = _find_domain_service(bootstrap, domain)
            if base_url is None:
                errors.append(
                    CollectorError(
                        code="rdap_service_not_found",
                        message=(
                            "The IANA bootstrap registry has no HTTPS RDAP service "
                            "for this TLD."
                        ),
                    )
                )
                return self._output(
                    started_at,
                    CollectorStatus.SKIPPED,
                    observations,
                    errors,
                    artifacts,
                )
            query_url = urljoin(
                base_url.rstrip("/") + "/", "domain/" + quote(domain, safe=".-")
            )
            response_bytes, response, response_source = self._fetch_json(
                query_url, deadline
            )
        except RdapCollectionError as exc:
            errors.append(
                CollectorError(code=exc.code, message=str(exc), retryable=exc.retryable)
            )
            return self._output(
                started_at,
                CollectorStatus.FAILED,
                observations,
                errors,
                artifacts,
            )

        bootstrap_path = f"10_snapshots/{snapshot_id}/rdap/iana-dns-bootstrap.json"
        response_path = f"10_snapshots/{snapshot_id}/rdap/domain-response.json"
        artifacts.extend(
            [
                PendingArtifact(
                    relative_path=bootstrap_path,
                    content=bootstrap_bytes,
                    media_type="application/json",
                    source="IANA RDAP DNS bootstrap registry",
                    metadata={
                        "collector": "rdap",
                        "collector_version": self.version,
                        "source_url": bootstrap_source,
                    },
                ),
                PendingArtifact(
                    relative_path=response_path,
                    content=response_bytes,
                    media_type="application/rdap+json",
                    source="authoritative domain RDAP response",
                    metadata={
                        "collector": "rdap",
                        "collector_version": self.version,
                        "source_url": response_source,
                        "queried_domain": domain,
                    },
                ),
            ]
        )
        observations.extend(_normalize_domain_response(response, response_source))
        observations.extend(
            [
                CollectorObservation(
                    category="rdap",
                    name="bootstrap.version",
                    value=_safe_value(bootstrap.get("version")),
                ),
                CollectorObservation(
                    category="rdap",
                    name="bootstrap.publication",
                    value=_safe_value(bootstrap.get("publication")),
                ),
            ]
        )
        return self._output(
            started_at,
            CollectorStatus.COMPLETE,
            observations,
            errors,
            artifacts,
        )

    def _bootstrap(self, deadline: float) -> tuple[bytes, dict[str, Any], str]:
        with self._cache_lock:
            cached = self._bootstrap_cache
            if cached and time.monotonic() - cached[0] < self.bootstrap_cache_seconds:
                return cached[1], cached[2], cached[3]
        content, payload, source = self._fetch_json(_BOOTSTRAP_URL, deadline)
        with self._cache_lock:
            self._bootstrap_cache = (time.monotonic(), content, payload, source)
        return content, payload, source

    def _fetch_json(
        self, initial_url: str, deadline: float
    ) -> tuple[bytes, dict[str, Any], str]:
        current_url = initial_url
        visited: set[str] = set()
        for hop in range(self.max_redirects + 1):
            try:
                target = normalize_target(current_url)
            except TargetValidationError as exc:
                raise RdapCollectionError(
                    "rdap_url_blocked", "An RDAP URL violated the collection policy."
                ) from exc
            if target.scheme != "https" or target.port not in {None, 443}:
                raise RdapCollectionError(
                    "rdap_url_blocked", "RDAP discovery and queries require standard HTTPS."
                )
            if target.normalized_url in visited:
                raise RdapCollectionError(
                    "rdap_redirect_loop", "The RDAP redirect chain contains a loop."
                )
            visited.add(target.normalized_url)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RdapCollectionError(
                    "rdap_timeout",
                    "The RDAP collection exceeded its total deadline.",
                    retryable=True,
                )
            port = target.port or 443
            try:
                addresses = self.address_resolver.resolve(
                    target.host, port, lifetime=remaining
                )
                address = _first_address(addresses)
                remaining = max(0.2, deadline - time.monotonic())
                exchange = self.client.request(
                    target,
                    address,
                    connect_timeout=min(self.connect_timeout_seconds, remaining / 2),
                    read_timeout=min(self.read_timeout_seconds, remaining / 2),
                    max_body_bytes=self.max_response_bytes,
                    accept=_RDAP_ACCEPT,
                    verify_tls=True,
                    request_range=False,
                )
            except TargetValidationError as exc:
                raise RdapCollectionError(
                    "rdap_network_blocked",
                    "An RDAP endpoint did not resolve exclusively to public addresses.",
                ) from exc
            except WebTransportError as exc:
                raise RdapCollectionError(
                    "rdap_transport_failed",
                    "The approved RDAP HTTPS exchange failed.",
                    retryable=exc.retryable,
                ) from exc
            if exchange.status in _REDIRECT_STATUSES:
                if not exchange.location or hop >= self.max_redirects:
                    raise RdapCollectionError(
                        "rdap_redirect_blocked",
                        "The RDAP redirect chain is incomplete or exceeded its limit.",
                    )
                current_url = urljoin(target.normalized_url, exchange.location)
                if len(current_url) > 4096:
                    raise RdapCollectionError(
                        "rdap_redirect_blocked", "An RDAP redirect URL was too long."
                    )
                continue
            if exchange.status != 200:
                raise RdapCollectionError(
                    "rdap_http_status",
                    f"The RDAP endpoint returned HTTP status {exchange.status}.",
                    retryable=exchange.status == 429 or exchange.status >= 500,
                )
            if exchange.body_skipped_reason or not exchange.body:
                raise RdapCollectionError(
                    "rdap_media_type_blocked",
                    "The RDAP response was not an allowed uncompressed JSON body.",
                )
            if exchange.body_truncated:
                raise RdapCollectionError(
                    "rdap_response_too_large",
                    f"The RDAP response exceeded {self.max_response_bytes} bytes.",
                )
            try:
                payload = json.loads(exchange.body.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
                raise RdapCollectionError(
                    "rdap_json_invalid", "The RDAP response was not valid bounded JSON."
                ) from exc
            if not isinstance(payload, dict):
                raise RdapCollectionError(
                    "rdap_json_invalid", "The RDAP response root was not a JSON object."
                )
            return exchange.body, payload, target.normalized_url
        raise RdapCollectionError(
            "rdap_redirect_blocked", "The RDAP redirect limit was reached."
        )

    def _output(
        self,
        started_at: datetime,
        status: CollectorStatus,
        observations: list[CollectorObservation],
        errors: list[CollectorError],
        artifacts: list[PendingArtifact],
    ) -> CollectorOutput:
        return CollectorOutput(
            result=CollectorResult(
                collector="rdap",
                version=self.version,
                status=status,
                started_at=started_at,
                finished_at=datetime.now(UTC),
                observations=observations[:250],
                artifacts=[artifact.relative_path for artifact in artifacts],
                errors=errors,
            ),
            artifacts=artifacts,
        )


def _find_domain_service(bootstrap: dict[str, Any], domain: str) -> str | None:
    tld = domain.rsplit(".", 1)[-1].lower()
    services = bootstrap.get("services")
    if not isinstance(services, list):
        raise RdapCollectionError(
            "rdap_bootstrap_invalid", "The IANA RDAP bootstrap registry is invalid."
        )
    for service in services[:5000]:
        if not isinstance(service, list) or len(service) != 2:
            continue
        entries, urls = service
        if not isinstance(entries, list) or not isinstance(urls, list):
            continue
        normalized_entries = {
            entry.lower().lstrip(".")
            for entry in entries[:500]
            if isinstance(entry, str)
        }
        if tld not in normalized_entries:
            continue
        for url in urls[:20]:
            if isinstance(url, str) and url.lower().startswith("https://"):
                try:
                    normalized = normalize_target(url)
                except TargetValidationError:
                    continue
                if normalized.scheme == "https" and normalized.port in {None, 443}:
                    return normalized.normalized_url
        return None
    return None


def _normalize_domain_response(
    payload: dict[str, Any], source_url: str
) -> list[CollectorObservation]:
    observations = [
        CollectorObservation(category="rdap", name="source_url", value=source_url)
    ]
    for key in ("objectClassName", "handle", "ldhName", "unicodeName"):
        value = payload.get(key)
        if isinstance(value, str):
            observations.append(
                CollectorObservation(
                    category="rdap", name=key, value=_safe_value(value)
                )
            )
    for status in _strings(payload.get("status"), limit=50):
        observations.append(
            CollectorObservation(category="rdap", name="status", value=status)
        )
    for event in _dicts(payload.get("events"), limit=100):
        action = event.get("eventAction")
        date = event.get("eventDate")
        if isinstance(action, str) and isinstance(date, str):
            observations.append(
                CollectorObservation(
                    category="rdap",
                    name=f"event.{_safe_value(action, limit=80)}",
                    value=_safe_value(date),
                )
            )
    for nameserver in _dicts(payload.get("nameservers"), limit=100):
        name = nameserver.get("ldhName") or nameserver.get("unicodeName")
        if isinstance(name, str):
            observations.append(
                CollectorObservation(
                    category="rdap", name="nameserver", value=_safe_value(name)
                )
            )
    secure_dns = payload.get("secureDNS")
    if isinstance(secure_dns, dict) and isinstance(
        secure_dns.get("delegationSigned"), bool
    ):
        observations.append(
            CollectorObservation(
                category="rdap",
                name="dnssec.delegation_signed",
                value=str(secure_dns["delegationSigned"]).lower(),
            )
        )
    observations.extend(_registrar_observations(payload.get("entities")))
    return observations


def _registrar_observations(
    value: Any, *, depth: int = 0
) -> list[CollectorObservation]:
    if depth >= 3:
        return []
    observations: list[CollectorObservation] = []
    for entity in _dicts(value, limit=100):
        roles = {role.lower() for role in _strings(entity.get("roles"), limit=20)}
        if "registrar" in roles:
            handle = entity.get("handle")
            if isinstance(handle, str):
                observations.append(
                    CollectorObservation(
                        category="rdap", name="registrar.handle", value=_safe_value(handle)
                    )
                )
            name = _vcard_value(entity.get("vcardArray"), "fn")
            if name:
                observations.append(
                    CollectorObservation(
                        category="rdap", name="registrar.name", value=name
                    )
                )
            for public_id in _dicts(entity.get("publicIds"), limit=20):
                identifier = public_id.get("identifier")
                id_type = public_id.get("type")
                if isinstance(identifier, str):
                    observations.append(
                        CollectorObservation(
                            category="rdap",
                            name=(
                                "registrar.public_id."
                                + _safe_value(id_type, limit=80).lower().replace(" ", "_")
                            ),
                            value=_safe_value(identifier),
                        )
                    )
        if "abuse" in roles:
            email = _vcard_value(entity.get("vcardArray"), "email")
            if email:
                observations.append(
                    CollectorObservation(
                        category="rdap", name="registrar.abuse_email", value=email
                    )
                )
        nested = entity.get("entities")
        if nested is not None:
            observations.extend(_registrar_observations(nested, depth=depth + 1)[:50])
    return observations[:100]


def _vcard_value(value: Any, property_name: str) -> str | None:
    if not isinstance(value, list) or len(value) != 2 or not isinstance(value[1], list):
        return None
    for item in value[1][:100]:
        if (
            isinstance(item, list)
            and len(item) >= 4
            and item[0] == property_name
            and isinstance(item[3], str)
        ):
            return _safe_value(item[3])
    return None


def _first_address(addresses: tuple[str, ...]) -> str:
    return sorted(
        addresses,
        key=lambda value: (
            ipaddress.ip_address(value).version,
            ipaddress.ip_address(value).packed,
        ),
    )[0]


def _safe_value(value: Any, *, limit: int = 2000) -> str:
    text = value if isinstance(value, str) else str(value or "")
    return "".join(
        character if ord(character) >= 32 and ord(character) != 127 else " "
        for character in text
    )[:limit]


def _strings(value: Any, *, limit: int) -> list[str]:
    if not isinstance(value, list):
        return []
    return [_safe_value(item) for item in value[:limit] if isinstance(item, str)]


def _dicts(value: Any, *, limit: int) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value[:limit] if isinstance(item, dict)]
