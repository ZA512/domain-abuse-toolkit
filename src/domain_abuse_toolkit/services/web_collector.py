from __future__ import annotations

import hashlib
import http.client
import ipaddress
import socket
import ssl
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote, urljoin

import dns.exception
import dns.resolver
from cryptography import x509

from domain_abuse_toolkit.models import (
    CollectorError,
    CollectorObservation,
    CollectorResult,
    CollectorStatus,
    NormalizedTarget,
)
from domain_abuse_toolkit.security.targets import (
    TargetValidationError,
    normalize_target,
    validate_resolved_addresses,
)
from domain_abuse_toolkit.services.collectors import CollectorBatchOutput
from domain_abuse_toolkit.services.evidence import PendingArtifact
from domain_abuse_toolkit.services.html_resources import extract_stylesheet_urls

_REDIRECT_STATUSES = {301, 302, 303, 307, 308}
_SAFE_RESPONSE_HEADERS = {
    "cache-control",
    "content-language",
    "content-length",
    "content-range",
    "content-encoding",
    "content-type",
    "date",
    "etag",
    "expires",
    "last-modified",
    "location",
    "server",
    "strict-transport-security",
}
_TEXTUAL_MEDIA_TYPES = {
    "application/json",
    "application/ld+json",
    "application/rdap+json",
    "application/xhtml+xml",
    "application/xml",
}
_HTML_MEDIA_TYPES = {"text/html", "application/xhtml+xml"}


class WebTransportError(ValueError):
    def __init__(self, code: str, message: str, *, retryable: bool = False) -> None:
        super().__init__(message)
        self.code = code
        self.retryable = retryable


@dataclass(frozen=True)
class TlsPeer:
    certificate_der: bytes
    protocol: str | None
    cipher: str | None


@dataclass(frozen=True)
class HttpExchange:
    requested_url: str
    peer_address: str
    status: int
    reason: str
    safe_headers: list[tuple[str, str]]
    location: str | None
    content_type: str
    body: bytes
    body_truncated: bool
    body_skipped_reason: str | None
    tls: TlsPeer | None


class BoundedAddressResolver:
    """Resolve all A/AAAA answers under a deadline and reject any non-public value."""

    def __init__(
        self,
        *,
        timeout_seconds: float = 2.0,
        lifetime_seconds: float = 5.0,
        resolver_factory: Callable[[], Any] = dns.resolver.Resolver,
    ) -> None:
        self.timeout_seconds = timeout_seconds
        self.lifetime_seconds = lifetime_seconds
        self.resolver_factory = resolver_factory

    def resolve(self, host: str, port: int, *, lifetime: float) -> tuple[str, ...]:
        try:
            literal = str(ipaddress.ip_address(host))
        except ValueError:
            literal = None
        if literal is not None:
            return validate_resolved_addresses([literal])

        resolver = self.resolver_factory()
        resolver.timeout = min(self.timeout_seconds, lifetime)
        deadline = time.monotonic() + min(self.lifetime_seconds, lifetime)
        addresses: list[str] = []
        for record_type in ("A", "AAAA"):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TargetValidationError("DNS resolution exceeded the collection deadline.")
            try:
                answer = resolver.resolve(
                    host,
                    record_type,
                    search=False,
                    lifetime=remaining,
                    raise_on_no_answer=False,
                )
            except dns.resolver.NXDOMAIN as exc:
                raise TargetValidationError("The target name does not exist.") from exc
            except (dns.exception.Timeout, dns.resolver.NoNameservers) as exc:
                raise TargetValidationError("DNS resolution failed within policy limits.") from exc
            except dns.exception.DNSException as exc:
                raise TargetValidationError("DNS resolution failed.") from exc
            if answer.rrset is not None:
                addresses.extend(item.to_text() for item in answer)
        return validate_resolved_addresses(addresses)


class DirectHttpClient:
    """Connect to an already validated IP while retaining the intended Host and TLS SNI."""

    user_agent = "DomainAbuseToolkit/0.1 passive-evidence"

    def request(
        self,
        target: NormalizedTarget,
        address: str,
        *,
        connect_timeout: float,
        read_timeout: float,
        max_body_bytes: int,
        accept: str | None = None,
        verify_tls: bool = False,
        request_range: bool = True,
    ) -> HttpExchange:
        accept_header = accept or (
            "text/html,application/xhtml+xml,application/json,"
            "text/plain;q=0.9,*/*;q=0.1"
        )
        if any(ord(character) < 32 or ord(character) == 127 for character in accept_header):
            raise WebTransportError(
                "http_request_invalid", "The HTTP Accept header was invalid."
            )
        range_header = f"Range: bytes=0-{max_body_bytes - 1}\r\n" if request_range else ""
        port = target.port or (443 if target.scheme == "https" else 80)
        raw_socket: socket.socket | None = None
        connection: socket.socket | ssl.SSLSocket | None = None
        tls_peer: TlsPeer | None = None
        try:
            raw_socket = socket.create_connection((address, port), timeout=connect_timeout)
            raw_socket.settimeout(read_timeout)
            connection = raw_socket
            if target.scheme == "https":
                context = (
                    ssl.create_default_context()
                    if verify_tls
                    else ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                )
                if not verify_tls:
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                context.minimum_version = ssl.TLSVersion.TLSv1_2
                connection = context.wrap_socket(raw_socket, server_hostname=target.host)
                certificate_der = connection.getpeercert(binary_form=True)
                if not certificate_der:
                    raise WebTransportError(
                        "tls_certificate_missing",
                        "The TLS peer did not provide a certificate.",
                    )
                cipher_info = connection.cipher()
                tls_peer = TlsPeer(
                    certificate_der=certificate_der,
                    protocol=connection.version(),
                    cipher=cipher_info[0] if cipher_info else None,
                )

            request_target = quote(
                target.path or "/", safe="/%:@!$&'()*+,;=-._~"
            )
            if target.query:
                request_target += "?" + quote(
                    target.query, safe="=&?/:@!$'()*+,;%-._~"
                )
            display_host = f"[{target.host}]" if ":" in target.host else target.host
            default_port = 443 if target.scheme == "https" else 80
            host_header = (
                f"{display_host}:{port}" if port != default_port else display_host
            )
            request_bytes = (
                f"GET {request_target} HTTP/1.1\r\n"
                f"Host: {host_header}\r\n"
                f"User-Agent: {self.user_agent}\r\n"
                f"Accept: {accept_header}\r\n"
                "Accept-Encoding: identity\r\n"
                f"{range_header}"
                "Connection: close\r\n\r\n"
            ).encode("ascii")
            connection.sendall(request_bytes)

            response = http.client.HTTPResponse(connection)
            response.begin()
            headers = response.getheaders()
            safe_headers = [
                (name.lower(), _safe_text(value, limit=2000))
                for name, value in headers
                if name.lower() in _SAFE_RESPONSE_HEADERS
            ]
            location = response.getheader("Location")
            content_type = (response.getheader("Content-Type") or "").split(";", 1)[
                0
            ].strip().lower()
            content_disposition = (
                response.getheader("Content-Disposition") or ""
            ).lower()
            content_encoding = (response.getheader("Content-Encoding") or "").lower()
            allowed_body = content_type.startswith("text/") or content_type in _TEXTUAL_MEDIA_TYPES
            body_skipped_reason = None
            if "attachment" in content_disposition:
                allowed_body = False
                body_skipped_reason = "attachment_content_disposition"
            elif content_encoding not in {"", "identity"}:
                allowed_body = False
                body_skipped_reason = "content_encoding_not_identity"
            elif not allowed_body:
                body_skipped_reason = "content_type_not_allowed"

            body = b""
            body_truncated = False
            if allowed_body:
                captured = response.read(max_body_bytes + 1)
                body_truncated = len(captured) > max_body_bytes
                body = captured[:max_body_bytes]
            return HttpExchange(
                requested_url=target.normalized_url,
                peer_address=address,
                status=response.status,
                reason=_safe_text(response.reason or "", limit=200),
                safe_headers=safe_headers,
                location=location,
                content_type=content_type or "application/octet-stream",
                body=body,
                body_truncated=body_truncated,
                body_skipped_reason=body_skipped_reason,
                tls=tls_peer,
            )
        except WebTransportError:
            raise
        except TimeoutError as exc:
            raise WebTransportError(
                "http_timeout",
                "The HTTP/TLS exchange exceeded the configured timeout.",
                retryable=True,
            ) from exc
        except ssl.SSLError as exc:
            raise WebTransportError(
                "tls_handshake_failed",
                "The TLS handshake failed within the approved policy.",
            ) from exc
        except (OSError, http.client.HTTPException, UnicodeError) as exc:
            raise WebTransportError(
                "http_exchange_failed",
                "The bounded HTTP exchange failed.",
                retryable=True,
            ) from exc
        finally:
            if connection is not None:
                connection.close()
            elif raw_socket is not None:
                raw_socket.close()


class WebCollector:
    version = "1.1"

    def __init__(
        self,
        *,
        address_resolver: BoundedAddressResolver | None = None,
        client: DirectHttpClient | None = None,
        connect_timeout_seconds: float = 5.0,
        read_timeout_seconds: float = 5.0,
        total_timeout_seconds: float = 30.0,
        max_redirects: int = 5,
        max_body_bytes: int = 256 * 1024,
        max_stylesheets: int = 8,
        max_stylesheet_bytes: int = 128 * 1024,
        max_stylesheet_total_bytes: int = 512 * 1024,
    ) -> None:
        self.address_resolver = address_resolver or BoundedAddressResolver()
        self.client = client or DirectHttpClient()
        self.connect_timeout_seconds = connect_timeout_seconds
        self.read_timeout_seconds = read_timeout_seconds
        self.total_timeout_seconds = total_timeout_seconds
        self.max_redirects = max_redirects
        self.max_body_bytes = max_body_bytes
        self.max_stylesheets = max_stylesheets
        self.max_stylesheet_bytes = max_stylesheet_bytes
        self.max_stylesheet_total_bytes = max_stylesheet_total_bytes

    def collect(self, target: NormalizedTarget, snapshot_id: str) -> CollectorBatchOutput:
        started_at = datetime.now(UTC)
        deadline = time.monotonic() + self.total_timeout_seconds
        current = target
        visited: set[str] = set()
        http_observations: list[CollectorObservation] = []
        tls_observations: list[CollectorObservation] = []
        http_errors: list[CollectorError] = []
        tls_errors: list[CollectorError] = []
        http_artifacts: list[PendingArtifact] = []
        tls_artifacts: list[PendingArtifact] = []
        exchange_count = 0
        tls_count = 0
        final_response_reached = False
        final_html_artifact: PendingArtifact | None = None

        for hop in range(self.max_redirects + 1):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                http_errors.append(
                    CollectorError(
                        code="http_total_timeout",
                        message="The passive web collection exceeded its total deadline.",
                        retryable=True,
                    )
                )
                break
            if current.normalized_url in visited:
                http_errors.append(
                    CollectorError(
                        code="redirect_loop",
                        message="The redirect chain contains a loop.",
                    )
                )
                break
            visited.add(current.normalized_url)
            port = current.port or (443 if current.scheme == "https" else 80)
            try:
                addresses = self.address_resolver.resolve(
                    current.host, port, lifetime=remaining
                )
                address = _first_address(addresses)
                remaining = max(0.2, deadline - time.monotonic())
                phase_budget = remaining / 2
                exchange = self.client.request(
                    current,
                    address,
                    connect_timeout=min(self.connect_timeout_seconds, phase_budget),
                    read_timeout=min(self.read_timeout_seconds, phase_budget),
                    max_body_bytes=self.max_body_bytes,
                )
            except TargetValidationError:
                http_errors.append(
                    CollectorError(
                        code="target_network_blocked",
                        message=(
                            "The current URL did not resolve exclusively to public addresses; "
                            "no connection was attempted."
                        ),
                    )
                )
                break
            except WebTransportError as exc:
                error = CollectorError(
                    code=exc.code, message=str(exc), retryable=exc.retryable
                )
                http_errors.append(error)
                if exc.code.startswith("tls_"):
                    tls_errors.append(error)
                break

            exchange_count += 1
            http_observations.extend(_http_observations(exchange, hop))
            if exchange.body:
                body_path = f"10_snapshots/{snapshot_id}/http/{hop:02d}-body.bin"
                body_artifact = PendingArtifact(
                    relative_path=body_path,
                    content=exchange.body,
                    media_type=exchange.content_type,
                    source=f"bounded HTTP response body hop {hop}",
                    metadata={
                        "collector": "http",
                        "collector_version": self.version,
                        "requested_url": exchange.requested_url,
                        "status": exchange.status,
                        "truncated": exchange.body_truncated,
                        "sha256": hashlib.sha256(exchange.body).hexdigest(),
                    },
                )
                http_artifacts.append(body_artifact)
                if (
                    exchange.status not in _REDIRECT_STATUSES
                    and exchange.content_type in _HTML_MEDIA_TYPES
                    and not exchange.body_truncated
                ):
                    final_html_artifact = body_artifact
            if exchange.body_truncated:
                http_errors.append(
                    CollectorError(
                        code="http_body_truncated",
                        message=(
                            f"The response body exceeded {self.max_body_bytes} bytes and "
                            "was truncated."
                        ),
                    )
                )

            if exchange.tls is not None:
                tls_count += 1
                cert_path = f"10_snapshots/{snapshot_id}/tls/{hop:02d}-certificate.der"
                tls_artifacts.append(
                    PendingArtifact(
                        relative_path=cert_path,
                        content=exchange.tls.certificate_der,
                        media_type="application/pkix-cert",
                        source=f"TLS leaf certificate hop {hop}",
                        metadata={
                            "collector": "tls",
                            "collector_version": self.version,
                            "requested_url": exchange.requested_url,
                        },
                    )
                )
                try:
                    tls_observations.extend(_tls_observations(exchange.tls, hop))
                except ValueError:
                    tls_errors.append(
                        CollectorError(
                            code="tls_certificate_parse_failed",
                            message="The captured TLS certificate could not be parsed.",
                        )
                    )

            if exchange.status not in _REDIRECT_STATUSES:
                final_response_reached = True
                break
            if not exchange.location:
                http_errors.append(
                    CollectorError(
                        code="redirect_location_missing",
                        message="A redirect response did not contain a Location header.",
                    )
                )
                break
            if hop >= self.max_redirects:
                http_errors.append(
                    CollectorError(
                        code="redirect_limit",
                        message=f"The redirect chain exceeded the limit of {self.max_redirects}.",
                    )
                )
                break
            redirect_value = urljoin(current.normalized_url, exchange.location)
            if len(redirect_value) > 4096:
                http_errors.append(
                    CollectorError(
                        code="redirect_invalid",
                        message="A redirect target exceeded the allowed URL length.",
                    )
                )
                break
            try:
                next_target = normalize_target(redirect_value)
            except TargetValidationError:
                http_errors.append(
                    CollectorError(
                        code="redirect_invalid",
                        message="A redirect target violated the URL collection policy.",
                    )
                )
                break
            if current.scheme == "https" and next_target.scheme == "http":
                http_errors.append(
                    CollectorError(
                        code="redirect_tls_downgrade",
                        message="The redirect chain downgraded from HTTPS to HTTP.",
                    )
                )
            current = next_target

        if final_html_artifact is not None:
            style_observations, style_artifacts, style_errors = self._collect_stylesheets(
                final_html_artifact,
                snapshot_id,
                deadline,
            )
            http_observations.extend(style_observations)
            http_artifacts.extend(style_artifacts)
            http_errors.extend(style_errors)

        finished_at = datetime.now(UTC)
        http_status = _result_status(
            completed=final_response_reached,
            produced=exchange_count > 0,
            errors=http_errors,
        )
        if tls_count == 0 and not tls_errors:
            tls_status = CollectorStatus.SKIPPED
        else:
            tls_status = _result_status(
                completed=tls_count > 0,
                produced=tls_count > 0,
                errors=tls_errors,
            )
        http_result = CollectorResult(
            collector="http",
            version=self.version,
            status=http_status,
            started_at=started_at,
            finished_at=finished_at,
            observations=http_observations,
            artifacts=[item.relative_path for item in http_artifacts],
            errors=http_errors,
        )
        tls_result = CollectorResult(
            collector="tls",
            version=self.version,
            status=tls_status,
            started_at=started_at,
            finished_at=finished_at,
            observations=tls_observations,
            artifacts=[item.relative_path for item in tls_artifacts],
            errors=tls_errors,
        )
        return CollectorBatchOutput(
            results=[http_result, tls_result],
            artifacts=[*http_artifacts, *tls_artifacts],
        )

    def _collect_stylesheets(
        self,
        document: PendingArtifact,
        snapshot_id: str,
        deadline: float,
    ) -> tuple[
        list[CollectorObservation], list[PendingArtifact], list[CollectorError]
    ]:
        document_url = str(document.metadata.get("requested_url", ""))
        urls = extract_stylesheet_urls(
            document.content,
            document_url,
            max_stylesheets=self.max_stylesheets + 1,
        )
        observations: list[CollectorObservation] = []
        artifacts: list[PendingArtifact] = []
        errors: list[CollectorError] = []
        if len(urls) > self.max_stylesheets:
            errors.append(
                CollectorError(
                    code="stylesheet_count_limit",
                    message=(
                        f"The document declared more than {self.max_stylesheets} "
                        "stylesheets; additional resources were not collected."
                    ),
                )
            )
            urls = urls[: self.max_stylesheets]
        total_bytes = 0
        for index, stylesheet_url in enumerate(urls):
            if total_bytes >= self.max_stylesheet_total_bytes:
                errors.append(
                    CollectorError(
                        code="stylesheet_total_limit",
                        message="The stylesheet collection reached its total byte limit.",
                    )
                )
                break
            try:
                current = normalize_target(stylesheet_url)
            except TargetValidationError:
                errors.append(
                    CollectorError(
                        code="stylesheet_url_invalid",
                        message="A stylesheet URL violated the collection policy.",
                    )
                )
                continue
            exchange: HttpExchange | None = None
            visited: set[str] = set()
            for hop in range(min(self.max_redirects, 3) + 1):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    errors.append(
                        CollectorError(
                            code="stylesheet_timeout",
                            message="Stylesheet collection exceeded the web deadline.",
                            retryable=True,
                        )
                    )
                    break
                if current.normalized_url in visited:
                    errors.append(
                        CollectorError(
                            code="stylesheet_redirect_loop",
                            message="A stylesheet redirect chain contained a loop.",
                        )
                    )
                    break
                visited.add(current.normalized_url)
                port = current.port or (443 if current.scheme == "https" else 80)
                try:
                    addresses = self.address_resolver.resolve(
                        current.host, port, lifetime=remaining
                    )
                    address = _first_address(addresses)
                    remaining = max(0.2, deadline - time.monotonic())
                    phase_budget = remaining / 2
                    exchange = self.client.request(
                        current,
                        address,
                        connect_timeout=min(self.connect_timeout_seconds, phase_budget),
                        read_timeout=min(self.read_timeout_seconds, phase_budget),
                        max_body_bytes=min(
                            self.max_stylesheet_bytes,
                            self.max_stylesheet_total_bytes - total_bytes,
                        ),
                        accept="text/css,*/*;q=0.1",
                    )
                except TargetValidationError:
                    errors.append(
                        CollectorError(
                            code="stylesheet_network_blocked",
                            message=(
                                "A stylesheet did not resolve exclusively to public "
                                "addresses; no connection was attempted."
                            ),
                        )
                    )
                    exchange = None
                    break
                except WebTransportError as exc:
                    errors.append(
                        CollectorError(
                            code="stylesheet_fetch_failed",
                            message="A bounded stylesheet request failed.",
                            retryable=exc.retryable,
                        )
                    )
                    exchange = None
                    break

                observations.extend(
                    [
                        CollectorObservation(
                            category="http",
                            name=f"stylesheet_{index}.url",
                            value=exchange.requested_url,
                        ),
                        CollectorObservation(
                            category="http",
                            name=f"stylesheet_{index}.status",
                            value=str(exchange.status),
                        ),
                    ]
                )
                if exchange.status not in _REDIRECT_STATUSES:
                    break
                if not exchange.location or hop >= min(self.max_redirects, 3):
                    errors.append(
                        CollectorError(
                            code="stylesheet_redirect_invalid",
                            message="A stylesheet redirect could not be followed safely.",
                        )
                    )
                    exchange = None
                    break
                redirected = urljoin(current.normalized_url, exchange.location)
                try:
                    next_target = normalize_target(redirected)
                except TargetValidationError:
                    errors.append(
                        CollectorError(
                            code="stylesheet_redirect_invalid",
                            message="A stylesheet redirect violated the URL policy.",
                        )
                    )
                    exchange = None
                    break
                if current.scheme == "https" and next_target.scheme == "http":
                    errors.append(
                        CollectorError(
                            code="stylesheet_tls_downgrade",
                            message="A stylesheet redirect attempted to downgrade HTTPS.",
                        )
                    )
                    exchange = None
                    break
                current = next_target

            if exchange is None:
                continue
            if not 200 <= exchange.status < 300 or exchange.content_type != "text/css":
                errors.append(
                    CollectorError(
                        code="stylesheet_response_invalid",
                        message="A stylesheet response was not a successful text/css resource.",
                    )
                )
                continue
            if not exchange.body or exchange.body_truncated:
                errors.append(
                    CollectorError(
                        code="stylesheet_body_incomplete",
                        message="A stylesheet body was empty or exceeded its byte limit.",
                    )
                )
                continue
            total_bytes += len(exchange.body)
            relative_path = f"10_snapshots/{snapshot_id}/http/styles/{index:02d}.css"
            artifacts.append(
                PendingArtifact(
                    relative_path=relative_path,
                    content=exchange.body,
                    media_type="text/css",
                    source="bounded external stylesheet response",
                    metadata={
                        "collector": "http",
                        "collector_version": self.version,
                        "resource_type": "stylesheet",
                        "stylesheet_url": stylesheet_url,
                        "requested_url": exchange.requested_url,
                        "status": exchange.status,
                        "truncated": False,
                        "sha256": hashlib.sha256(exchange.body).hexdigest(),
                    },
                )
            )
            observations.append(
                CollectorObservation(
                    category="http",
                    name=f"stylesheet_{index}.body_sha256",
                    value=hashlib.sha256(exchange.body).hexdigest(),
                )
            )
        return observations, artifacts, errors


def _first_address(addresses: tuple[str, ...]) -> str:
    return sorted(
        addresses,
        key=lambda value: (
            ipaddress.ip_address(value).version,
            ipaddress.ip_address(value).packed,
        ),
    )[0]


def _safe_text(value: str, *, limit: int) -> str:
    sanitized = "".join(
        character if ord(character) >= 32 and ord(character) != 127 else " "
        for character in value
    )
    return sanitized[:limit]


def _http_observations(exchange: HttpExchange, hop: int) -> list[CollectorObservation]:
    observations = [
        CollectorObservation(
            category="http", name=f"hop_{hop}.url", value=exchange.requested_url
        ),
        CollectorObservation(
            category="http", name=f"hop_{hop}.peer_address", value=exchange.peer_address
        ),
        CollectorObservation(
            category="http", name=f"hop_{hop}.status", value=str(exchange.status)
        ),
        CollectorObservation(
            category="http", name=f"hop_{hop}.reason", value=exchange.reason
        ),
        CollectorObservation(
            category="http",
            name=f"hop_{hop}.body_sha256",
            value=hashlib.sha256(exchange.body).hexdigest(),
        ),
    ]
    if exchange.body_skipped_reason:
        observations.append(
            CollectorObservation(
                category="http",
                name=f"hop_{hop}.body_skipped",
                value=exchange.body_skipped_reason,
            )
        )
    for name, value in exchange.safe_headers:
        observations.append(
            CollectorObservation(
                category="http", name=f"hop_{hop}.header.{name}", value=value
            )
        )
    return observations


def _tls_observations(peer: TlsPeer, hop: int) -> list[CollectorObservation]:
    certificate = x509.load_der_x509_certificate(peer.certificate_der)
    observations = [
        CollectorObservation(
            category="tls",
            name=f"hop_{hop}.certificate_sha256",
            value=hashlib.sha256(peer.certificate_der).hexdigest(),
        ),
        CollectorObservation(
            category="tls", name=f"hop_{hop}.subject", value=certificate.subject.rfc4514_string()
        ),
        CollectorObservation(
            category="tls", name=f"hop_{hop}.issuer", value=certificate.issuer.rfc4514_string()
        ),
        CollectorObservation(
            category="tls",
            name=f"hop_{hop}.not_before",
            value=certificate.not_valid_before_utc.isoformat(),
        ),
        CollectorObservation(
            category="tls",
            name=f"hop_{hop}.not_after",
            value=certificate.not_valid_after_utc.isoformat(),
        ),
        CollectorObservation(
            category="tls",
            name=f"hop_{hop}.validation",
            value="not_performed_evidence_capture_only",
        ),
    ]
    if peer.protocol:
        observations.append(
            CollectorObservation(
                category="tls", name=f"hop_{hop}.protocol", value=peer.protocol
            )
        )
    if peer.cipher:
        observations.append(
            CollectorObservation(
                category="tls", name=f"hop_{hop}.cipher", value=peer.cipher
            )
        )
    try:
        alternative_names = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
    except x509.ExtensionNotFound:
        alternative_names = None
    if alternative_names is not None:
        san_values = [
            *alternative_names.get_values_for_type(x509.DNSName),
            *(str(value) for value in alternative_names.get_values_for_type(x509.IPAddress)),
        ]
        for value in sorted(san_values)[:100]:
            observations.append(
                CollectorObservation(
                    category="tls", name=f"hop_{hop}.san", value=value
                )
            )
    return observations


def _result_status(
    *, completed: bool, produced: bool, errors: list[CollectorError]
) -> CollectorStatus:
    if completed and not errors:
        return CollectorStatus.COMPLETE
    if produced:
        return CollectorStatus.PARTIAL
    return CollectorStatus.FAILED
