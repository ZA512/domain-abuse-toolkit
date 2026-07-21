from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from domain_abuse_toolkit.models import CollectorStatus
from domain_abuse_toolkit.security.targets import TargetValidationError, normalize_target
from domain_abuse_toolkit.services.web_collector import (
    BoundedAddressResolver,
    HttpExchange,
    TlsPeer,
    WebCollector,
)


class FakeAddressResolver:
    def __init__(self, answers: dict[str, tuple[str, ...] | Exception]) -> None:
        self.answers = answers
        self.calls: list[tuple[str, int]] = []

    def resolve(self, host: str, port: int, *, lifetime: float) -> tuple[str, ...]:
        assert lifetime > 0
        self.calls.append((host, port))
        answer = self.answers[host]
        if isinstance(answer, Exception):
            raise answer
        return answer


class FakeHttpClient:
    def __init__(self, exchanges: list[HttpExchange]) -> None:
        self.exchanges = exchanges
        self.calls: list[tuple[str, str, int]] = []

    def request(
        self,
        target,  # type: ignore[no-untyped-def]
        address: str,
        *,
        connect_timeout: float,
        read_timeout: float,
        max_body_bytes: int,
        accept: str | None = None,
    ) -> HttpExchange:
        assert connect_timeout > 0
        assert read_timeout > 0
        self.calls.append((target.normalized_url, address, max_body_bytes))
        return self.exchanges.pop(0)


def _certificate_der() -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.net")])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("example.net")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.DER)


def _exchange(
    url: str,
    *,
    status: int = 200,
    location: str | None = None,
    body: bytes = b"ok",
    truncated: bool = False,
    tls: TlsPeer | None = None,
    content_type: str = "text/html",
) -> HttpExchange:
    headers = [("content-type", content_type)]
    if location:
        headers.append(("location", location))
    return HttpExchange(
        requested_url=url,
        peer_address="8.8.8.8",
        status=status,
        reason="OK",
        safe_headers=headers,
        location=location,
        content_type=content_type,
        body=body,
        body_truncated=truncated,
        body_skipped_reason=None,
        tls=tls,
    )


def test_web_collector_revalidates_redirect_and_records_tls_downgrade() -> None:
    certificate = _certificate_der()
    resolver = FakeAddressResolver(
        {"example.net": ("8.8.8.8",), "next.example.net": ("1.1.1.1",)}
    )
    client = FakeHttpClient(
        [
            _exchange(
                "https://example.net/start",
                status=302,
                location="http://next.example.net/final",
                body=b"",
                tls=TlsPeer(certificate, "TLSv1.3", "TLS_AES_256_GCM_SHA384"),
            ),
            _exchange("http://next.example.net/final", body=b"final"),
        ]
    )
    collector = WebCollector(address_resolver=resolver, client=client)

    output = collector.collect(normalize_target("https://example.net/start"), "SNP-TEST")

    http_result, tls_result = output.results
    assert http_result.status == CollectorStatus.PARTIAL
    assert any(error.code == "redirect_tls_downgrade" for error in http_result.errors)
    assert tls_result.status == CollectorStatus.COMPLETE
    assert any(item.name == "hop_0.san" for item in tls_result.observations)
    assert resolver.calls == [("example.net", 443), ("next.example.net", 80)]
    assert [call[1] for call in client.calls] == ["8.8.8.8", "1.1.1.1"]
    assert len(output.artifacts) == 2


def test_private_redirect_is_blocked_before_a_second_connection() -> None:
    resolver = FakeAddressResolver(
        {
            "example.net": ("8.8.8.8",),
            "127.0.0.1": TargetValidationError("prohibited"),
        }
    )
    client = FakeHttpClient(
        [
            _exchange(
                "https://example.net/",
                status=302,
                location="http://127.0.0.1/admin",
                body=b"",
            )
        ]
    )

    output = WebCollector(address_resolver=resolver, client=client).collect(
        normalize_target("https://example.net/"), "SNP-TEST"
    )

    assert output.results[0].status == CollectorStatus.PARTIAL
    assert output.results[0].errors[-1].code == "target_network_blocked"
    assert len(client.calls) == 1
    assert resolver.calls[-1] == ("127.0.0.1", 80)


def test_bounded_body_is_marked_partial_and_stored_at_the_limit() -> None:
    resolver = FakeAddressResolver({"example.net": ("8.8.8.8",)})
    client = FakeHttpClient(
        [_exchange("https://example.net/", body=b"1234", truncated=True)]
    )

    output = WebCollector(
        address_resolver=resolver, client=client, max_body_bytes=4
    ).collect(normalize_target("https://example.net/"), "SNP-TEST")

    assert output.results[0].status == CollectorStatus.PARTIAL
    assert output.results[0].errors[0].code == "http_body_truncated"
    assert output.artifacts[0].content == b"1234"


def test_public_stylesheet_is_collected_as_bounded_original_evidence() -> None:
    resolver = FakeAddressResolver(
        {"example.net": ("8.8.8.8",), "cdn.example.net": ("1.1.1.1",)}
    )
    client = FakeHttpClient(
        [
            _exchange(
                "https://example.net/",
                body=b'<link rel="stylesheet" href="https://cdn.example.net/app.css">',
            ),
            _exchange(
                "https://cdn.example.net/app.css",
                body=b"body { color: red; }",
                content_type="text/css",
            ),
        ]
    )

    output = WebCollector(address_resolver=resolver, client=client).collect(
        normalize_target("https://example.net/"), "SNP-TEST"
    )

    stylesheet = next(
        artifact for artifact in output.artifacts if artifact.media_type == "text/css"
    )
    assert output.results[0].status == CollectorStatus.COMPLETE
    assert stylesheet.content == b"body { color: red; }"
    assert stylesheet.metadata["stylesheet_url"] == "https://cdn.example.net/app.css"
    assert stylesheet.metadata["resource_type"] == "stylesheet"
    assert resolver.calls == [("example.net", 443), ("cdn.example.net", 443)]


def test_private_stylesheet_is_blocked_before_connection() -> None:
    resolver = FakeAddressResolver(
        {
            "example.net": ("8.8.8.8",),
            "private.example.net": TargetValidationError("prohibited"),
        }
    )
    client = FakeHttpClient(
        [
            _exchange(
                "https://example.net/",
                body=b'<link rel="stylesheet" href="http://private.example.net/app.css">',
            )
        ]
    )

    output = WebCollector(address_resolver=resolver, client=client).collect(
        normalize_target("https://example.net/"), "SNP-TEST"
    )

    assert output.results[0].status == CollectorStatus.PARTIAL
    assert output.results[0].errors[-1].code == "stylesheet_network_blocked"
    assert len(client.calls) == 1


class FakeDnsRecord:
    def __init__(self, value: str) -> None:
        self.value = value

    def to_text(self) -> str:
        return self.value


class FakeDnsAnswer(list[FakeDnsRecord]):
    def __init__(self, values: list[str]) -> None:
        super().__init__(FakeDnsRecord(value) for value in values)
        self.rrset = object() if values else None


class FakeDnsResolver:
    timeout = 0.0

    def resolve(self, _host: str, record_type: str, **_kwargs):  # type: ignore[no-untyped-def]
        return FakeDnsAnswer(
            ["8.8.8.8", "127.0.0.1"] if record_type == "A" else []
        )


def test_bounded_address_resolver_rejects_mixed_public_private_answers() -> None:
    resolver = BoundedAddressResolver(resolver_factory=FakeDnsResolver)

    with pytest.raises(TargetValidationError, match="non-public"):
        resolver.resolve("example.net", 443, lifetime=2)
