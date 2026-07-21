from __future__ import annotations

import ipaddress
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import dns.exception
import dns.resolver

from domain_abuse_toolkit.models import (
    CollectorError,
    CollectorObservation,
    CollectorResult,
    CollectorStatus,
    NormalizedTarget,
)
from domain_abuse_toolkit.security.targets import (
    TargetValidationError,
    validate_resolved_addresses,
)
from domain_abuse_toolkit.services.evidence import PendingArtifact

_RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT")


@dataclass(frozen=True)
class CollectorOutput:
    result: CollectorResult
    artifacts: list[PendingArtifact]


class DnsCollector:
    """Bounded passive DNS collector that preserves normalized and wire results."""

    version = "1.0"

    def __init__(
        self,
        *,
        timeout_seconds: float = 2.0,
        lifetime_seconds: float = 5.0,
        max_records_per_type: int = 50,
        resolver_factory: Callable[[], Any] = dns.resolver.Resolver,
    ) -> None:
        self.timeout_seconds = timeout_seconds
        self.lifetime_seconds = lifetime_seconds
        self.max_records_per_type = max_records_per_type
        self.resolver_factory = resolver_factory

    def collect(self, target: NormalizedTarget, snapshot_id: str) -> CollectorOutput:
        started_at = datetime.now(UTC)
        observations: list[CollectorObservation] = []
        errors: list[CollectorError] = []
        artifacts: list[PendingArtifact] = []

        try:
            literal_address = str(ipaddress.ip_address(target.host))
        except ValueError:
            literal_address = None

        if literal_address is not None:
            try:
                validate_resolved_addresses([literal_address])
            except TargetValidationError:
                errors.append(
                    CollectorError(
                        code="prohibited_address",
                        message="The target is a non-public or prohibited IP address.",
                    )
                )
                return self._output(
                    started_at, CollectorStatus.FAILED, observations, errors, artifacts
                )
            record_type = "AAAA" if ":" in literal_address else "A"
            observations.append(
                CollectorObservation(
                    category="dns",
                    name=target.host,
                    value=literal_address,
                    record_type=record_type,
                )
            )
            return self._output(
                started_at, CollectorStatus.COMPLETE, observations, errors, artifacts
            )

        resolver = self.resolver_factory()
        resolver.timeout = self.timeout_seconds
        address_values: list[str] = []
        fatal = False

        for record_type in _RECORD_TYPES:
            try:
                answer = resolver.resolve(
                    target.host,
                    record_type,
                    search=False,
                    lifetime=self.lifetime_seconds,
                    raise_on_no_answer=False,
                )
            except dns.resolver.NXDOMAIN:
                errors.append(
                    CollectorError(
                        code="nxdomain",
                        message="The target name does not exist according to the resolver.",
                    )
                )
                fatal = True
                break
            except dns.exception.Timeout:
                errors.append(
                    CollectorError(
                        code="dns_timeout",
                        message=f"The {record_type} DNS query exceeded the configured lifetime.",
                        retryable=True,
                    )
                )
                continue
            except dns.resolver.NoNameservers:
                errors.append(
                    CollectorError(
                        code="dns_nameserver_failure",
                        message=f"No nameserver could answer the {record_type} DNS query.",
                        retryable=True,
                    )
                )
                continue
            except dns.exception.DNSException:
                errors.append(
                    CollectorError(
                        code="dns_query_failure",
                        message=f"The {record_type} DNS query failed.",
                        retryable=True,
                    )
                )
                continue

            if answer.rrset is None:
                continue
            ttl = int(answer.rrset.ttl)
            values = sorted({item.to_text() for item in answer})
            if len(values) > self.max_records_per_type:
                errors.append(
                    CollectorError(
                        code="dns_record_limit",
                        message=(
                            f"The {record_type} answer exceeded the limit of "
                            f"{self.max_records_per_type} records and was truncated."
                        ),
                    )
                )
                values = values[: self.max_records_per_type]
            for value in values:
                observations.append(
                    CollectorObservation(
                        category="dns",
                        name=target.host,
                        value=value,
                        record_type=record_type,
                        ttl=ttl,
                    )
                )
                if record_type in {"A", "AAAA"}:
                    address_values.append(value)

            wire = answer.response.to_wire()
            relative_path = (
                f"10_snapshots/{snapshot_id}/dns/{record_type.lower()}-response.dns"
            )
            artifacts.append(
                PendingArtifact(
                    relative_path=relative_path,
                    content=wire,
                    media_type="application/dns-message",
                    source=f"passive DNS {record_type} response",
                    metadata={
                        "collector": "dns",
                        "collector_version": self.version,
                        "query_name": target.host,
                        "record_type": record_type,
                    },
                )
            )

        if not fatal:
            try:
                validate_resolved_addresses(address_values)
            except TargetValidationError:
                code = "prohibited_address" if address_values else "no_address_records"
                message = (
                    "DNS returned a non-public or prohibited address; later network "
                    "collectors must not connect."
                    if address_values
                    else "The target did not return a public A or AAAA address."
                )
                errors.append(CollectorError(code=code, message=message))
                fatal = True

        status = (
            CollectorStatus.FAILED
            if fatal
            else CollectorStatus.PARTIAL
            if errors
            else CollectorStatus.COMPLETE
        )
        return self._output(started_at, status, observations, errors, artifacts)

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
                collector="dns",
                version=self.version,
                status=status,
                started_at=started_at,
                finished_at=datetime.now(UTC),
                observations=observations,
                artifacts=[artifact.relative_path for artifact in artifacts],
                errors=errors,
            ),
            artifacts=artifacts,
        )
