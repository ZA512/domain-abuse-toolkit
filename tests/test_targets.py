import pytest

from domain_abuse_toolkit.security.targets import (
    TargetValidationError,
    is_public_address,
    normalize_target,
    resolve_public_target,
    validate_resolved_addresses,
)


def test_normalize_preserves_exact_path_and_query() -> None:
    target = normalize_target("https://Login.Example.CO.UK/account/reset?source=email#ignored")

    assert target.exact_input.endswith("#ignored")
    assert target.normalized_url == "https://login.example.co.uk/account/reset?source=email"
    assert target.host == "login.example.co.uk"
    assert target.registrable_domain == "example.co.uk"
    assert target.path == "/account/reset"
    assert target.query == "source=email"


@pytest.mark.parametrize(
    "value",
    [
        "ftp://example.com/file",
        "https://user:password@example.com/",
        "https://example.com:8443/",
        "https://example.com/path with space",
        "https://example.com\\@127.0.0.1/",
        "file:///etc/passwd",
    ],
)
def test_normalize_rejects_prohibited_targets(value: str) -> None:
    with pytest.raises(TargetValidationError):
        normalize_target(value)


@pytest.mark.parametrize("value", ["127.0.0.1", "10.0.0.1", "169.254.169.254", "192.0.2.1", "::1"])
def test_non_public_addresses_are_rejected(value: str) -> None:
    assert not is_public_address(value)
    with pytest.raises(TargetValidationError):
        validate_resolved_addresses([value])


def test_public_address_is_allowed() -> None:
    assert validate_resolved_addresses(["8.8.8.8"]) == ("8.8.8.8",)


def test_resolver_rejects_mixed_public_and_private_answers() -> None:
    target = normalize_target("https://example.com/")

    def fake_resolver(_host: str, _port: int | None) -> list[tuple]:
        return [
            (2, 1, 6, "", ("8.8.8.8", 443)),
            (2, 1, 6, "", ("127.0.0.1", 443)),
        ]

    with pytest.raises(TargetValidationError):
        resolve_public_target(target, resolver=fake_resolver)
