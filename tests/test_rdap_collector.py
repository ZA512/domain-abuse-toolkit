import json

from domain_abuse_toolkit.models import CollectorStatus
from domain_abuse_toolkit.security.targets import TargetValidationError, normalize_target
from domain_abuse_toolkit.services.rdap_collector import RdapCollector
from domain_abuse_toolkit.services.web_collector import HttpExchange


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
        self.calls: list[tuple[str, str, str | None, bool, bool]] = []

    def request(
        self,
        target,  # type: ignore[no-untyped-def]
        address: str,
        *,
        connect_timeout: float,
        read_timeout: float,
        max_body_bytes: int,
        accept: str | None = None,
        verify_tls: bool = False,
        request_range: bool = True,
    ) -> HttpExchange:
        assert connect_timeout > 0
        assert read_timeout > 0
        assert max_body_bytes > 0
        self.calls.append(
            (target.normalized_url, address, accept, verify_tls, request_range)
        )
        return self.exchanges.pop(0)


def _exchange(
    url: str,
    payload: object,
    *,
    status: int = 200,
    location: str | None = None,
    truncated: bool = False,
) -> HttpExchange:
    body = json.dumps(payload).encode()
    return HttpExchange(
        requested_url=url,
        peer_address="8.8.8.8",
        status=status,
        reason="OK",
        safe_headers=[("content-type", "application/rdap+json")],
        location=location,
        content_type="application/rdap+json",
        body=body,
        body_truncated=truncated,
        body_skipped_reason=None,
        tls=None,
    )


def _bootstrap(service_url: str = "https://rdap.example/") -> dict[str, object]:
    return {
        "version": "1.0",
        "publication": "2026-07-21T00:00:00Z",
        "services": [[["com"], [service_url]]],
    }


def test_rdap_collects_authoritative_registration_without_displaying_registrant() -> None:
    resolver = FakeAddressResolver(
        {
            "data.iana.org": ("192.0.43.8",),
            "rdap.example": ("8.8.8.8",),
        }
    )
    response = {
        "objectClassName": "domain",
        "handle": "EXAMPLE-COM",
        "ldhName": "example.com",
        "status": ["client transfer prohibited"],
        "events": [
            {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"}
        ],
        "nameservers": [{"ldhName": "A.IANA-SERVERS.NET"}],
        "secureDNS": {"delegationSigned": True},
        "entities": [
            {
                "roles": ["registrar"],
                "handle": "376",
                "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar"]]],
                "publicIds": [{"type": "IANA Registrar ID", "identifier": "376"}],
                "entities": [
                    {
                        "roles": ["abuse"],
                        "vcardArray": [
                            "vcard",
                            [["email", {}, "text", "abuse@registrar.example"]],
                        ],
                    }
                ],
            },
            {
                "roles": ["registrant"],
                "vcardArray": [
                    "vcard",
                    [["email", {}, "text", "private-owner@example.com"]],
                ],
            },
        ],
    }
    client = FakeHttpClient(
        [
            _exchange("https://data.iana.org/rdap/dns.json", _bootstrap()),
            _exchange("https://rdap.example/domain/example.com", response),
        ]
    )

    output = RdapCollector(address_resolver=resolver, client=client).collect(
        normalize_target("https://login.example.com/path"), "SNP-TEST"
    )

    assert output.result.status == CollectorStatus.COMPLETE
    values = {item.value for item in output.result.observations}
    assert "Example Registrar" in values
    assert "abuse@registrar.example" in values
    assert "private-owner@example.com" not in values
    assert len(output.artifacts) == 2
    assert all(call[3] is True for call in client.calls)
    assert all(call[4] is False for call in client.calls)
    assert [call[1] for call in client.calls] == ["192.0.43.8", "8.8.8.8"]


def test_rdap_skips_tld_without_an_https_bootstrap_service() -> None:
    resolver = FakeAddressResolver({"data.iana.org": ("192.0.43.8",)})
    client = FakeHttpClient(
        [_exchange("https://data.iana.org/rdap/dns.json", _bootstrap("http://rdap.example/"))]
    )

    output = RdapCollector(address_resolver=resolver, client=client).collect(
        normalize_target("https://example.com/"), "SNP-TEST"
    )

    assert output.result.status == CollectorStatus.SKIPPED
    assert output.result.errors[0].code == "rdap_service_not_found"
    assert output.artifacts == []


def test_rdap_redirect_to_a_private_endpoint_is_blocked_before_connection() -> None:
    resolver = FakeAddressResolver(
        {
            "data.iana.org": ("192.0.43.8",),
            "rdap.example": ("8.8.8.8",),
            "127.0.0.1": TargetValidationError("prohibited"),
        }
    )
    client = FakeHttpClient(
        [
            _exchange("https://data.iana.org/rdap/dns.json", _bootstrap()),
            _exchange(
                "https://rdap.example/domain/example.com",
                {},
                status=302,
                location="https://127.0.0.1/private",
            ),
        ]
    )

    output = RdapCollector(address_resolver=resolver, client=client).collect(
        normalize_target("https://example.com/"), "SNP-TEST"
    )

    assert output.result.status == CollectorStatus.FAILED
    assert output.result.errors[0].code == "rdap_network_blocked"
    assert len(client.calls) == 2
    assert resolver.calls[-1] == ("127.0.0.1", 443)


def test_rdap_rejects_a_truncated_response_without_persisting_it() -> None:
    resolver = FakeAddressResolver(
        {
            "data.iana.org": ("192.0.43.8",),
            "rdap.example": ("8.8.8.8",),
        }
    )
    client = FakeHttpClient(
        [
            _exchange("https://data.iana.org/rdap/dns.json", _bootstrap()),
            _exchange(
                "https://rdap.example/domain/example.com", {}, truncated=True
            ),
        ]
    )

    output = RdapCollector(address_resolver=resolver, client=client).collect(
        normalize_target("https://example.com/"), "SNP-TEST"
    )

    assert output.result.status == CollectorStatus.FAILED
    assert output.result.errors[0].code == "rdap_response_too_large"
    assert output.artifacts == []
