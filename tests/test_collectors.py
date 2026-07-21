import threading
from datetime import UTC, datetime

import dns.exception
import pytest

from domain_abuse_toolkit.models import (
    CaseCreate,
    CollectorObservation,
    CollectorResult,
    CollectorStatus,
)
from domain_abuse_toolkit.security.targets import normalize_target
from domain_abuse_toolkit.services.cases import CaseService
from domain_abuse_toolkit.services.collection_jobs import (
    CollectionJobService,
    CollectionQueueFullError,
)
from domain_abuse_toolkit.services.collectors import CollectorOutput, DnsCollector
from domain_abuse_toolkit.services.drafts import DraftService
from domain_abuse_toolkit.services.evidence import EvidenceStore, PendingArtifact


class FakeRecord:
    def __init__(self, value: str) -> None:
        self.value = value

    def to_text(self) -> str:
        return self.value


class FakeRrset:
    ttl = 300


class FakeMessage:
    def __init__(self, wire: bytes) -> None:
        self.wire = wire

    def to_wire(self) -> bytes:
        return self.wire


class FakeAnswer(list[FakeRecord]):
    def __init__(self, record_type: str, values: list[str]) -> None:
        super().__init__(FakeRecord(value) for value in values)
        self.rrset = FakeRrset() if values else None
        self.response = FakeMessage(f"wire-{record_type}".encode())


class FakeResolver:
    def __init__(self, answers: dict[str, list[str] | Exception]) -> None:
        self.answers = answers
        self.timeout = 0.0
        self.calls: list[tuple[str, float, bool]] = []

    def resolve(
        self,
        _host: str,
        record_type: str,
        *,
        search: bool,
        lifetime: float,
        raise_on_no_answer: bool,
    ) -> FakeAnswer:
        self.calls.append((record_type, lifetime, search))
        value = self.answers.get(record_type, [])
        if isinstance(value, Exception):
            raise value
        return FakeAnswer(record_type, value)


def _collector(resolver: FakeResolver) -> DnsCollector:
    return DnsCollector(
        timeout_seconds=1.5,
        lifetime_seconds=4,
        max_records_per_type=10,
        resolver_factory=lambda: resolver,
    )


def test_dns_collector_preserves_wire_answers_and_public_addresses() -> None:
    resolver = FakeResolver(
        {
            "A": ["8.8.8.8"],
            "AAAA": ["2001:4860:4860::8888"],
            "MX": ["10 mail.example.net."],
        }
    )

    output = _collector(resolver).collect(
        normalize_target("https://login.example.net/path"), "SNP-TEST"
    )

    assert output.result.status == CollectorStatus.COMPLETE
    assert {item.record_type for item in output.result.observations} == {"A", "AAAA", "MX"}
    assert {item.relative_path for item in output.artifacts} == {
        "10_snapshots/SNP-TEST/dns/a-response.dns",
        "10_snapshots/SNP-TEST/dns/aaaa-response.dns",
        "10_snapshots/SNP-TEST/dns/mx-response.dns",
    }
    assert resolver.timeout == 1.5
    assert all(lifetime == 4 and search is False for _, lifetime, search in resolver.calls)


def test_dns_collector_blocks_private_answers_and_keeps_structured_failure() -> None:
    output = _collector(FakeResolver({"A": ["8.8.8.8", "127.0.0.1"]})).collect(
        normalize_target("https://example.net/"), "SNP-TEST"
    )

    assert output.result.status == CollectorStatus.FAILED
    assert output.result.errors[-1].code == "prohibited_address"
    assert "127.0.0.1" not in output.result.errors[-1].message


def test_dns_timeout_is_partial_when_a_public_address_was_collected() -> None:
    output = _collector(
        FakeResolver({"A": ["8.8.8.8"], "AAAA": dns.exception.Timeout()})
    ).collect(normalize_target("https://example.net/"), "SNP-TEST")

    assert output.result.status == CollectorStatus.PARTIAL
    assert output.result.errors[0].code == "dns_timeout"
    assert output.result.errors[0].retryable is True


class SuccessfulCollector:
    version = "test"

    def collect(self, _target, snapshot_id: str) -> CollectorOutput:  # type: ignore[no-untyped-def]
        now = datetime.now(UTC)
        path = f"10_snapshots/{snapshot_id}/dns/a-response.dns"
        return CollectorOutput(
            result=CollectorResult(
                collector="dns",
                version=self.version,
                status=CollectorStatus.COMPLETE,
                started_at=now,
                finished_at=now,
                observations=[
                    CollectorObservation(
                        category="dns",
                        name="example.net",
                        value="8.8.8.8",
                        record_type="A",
                        ttl=300,
                    )
                ],
                artifacts=[path],
            ),
            artifacts=[
                PendingArtifact(
                    relative_path=path,
                    content=b"synthetic dns wire response",
                    media_type="application/dns-message",
                    source="synthetic collector test",
                )
            ],
        )


class BlockingCollector(SuccessfulCollector):
    def __init__(self) -> None:
        self.started = threading.Event()
        self.release = threading.Event()

    def collect(self, target, snapshot_id: str) -> CollectorOutput:  # type: ignore[no-untyped-def]
        self.started.set()
        assert self.release.wait(timeout=5)
        return super().collect(target, snapshot_id)


def test_collection_job_persists_snapshot_and_survives_restart(tmp_path) -> None:  # type: ignore[no-untyped-def]
    service = CaseService(EvidenceStore(tmp_path), DraftService())
    case = service.create(
        CaseCreate(
            target="https://login.example.net/",
            brand="Example Brand",
            legit_url="https://www.example.com/",
        )
    )
    jobs = CollectionJobService(service, SuccessfulCollector())

    queued = jobs.start_dns(case.id)
    finished = jobs.wait(queued.id)

    assert finished.status == CollectorStatus.COMPLETE
    assert len(case.snapshots) == 1
    assert service.evidence_store.verify_case(case.id) == []

    restarted = CaseService(EvidenceStore(tmp_path), DraftService())
    restored = restarted.get(case.id)
    assert restored.snapshots[0].id == queued.snapshot_id
    assert restored.snapshots[0].results[0].observations[0].value == "8.8.8.8"
    assert len(restarted.history(case.id)) == 1


def test_collection_queue_has_a_global_pending_limit(tmp_path) -> None:  # type: ignore[no-untyped-def]
    service = CaseService(EvidenceStore(tmp_path), DraftService())
    cases = [
        service.create(
            CaseCreate(
                target=f"https://login-{index}.example.net/",
                brand="Example Brand",
                legit_url="https://www.example.com/",
            )
        )
        for index in range(2)
    ]
    collector = BlockingCollector()
    jobs = CollectionJobService(
        service, collector, max_workers=1, max_pending_jobs=1
    )

    first = jobs.start_dns(cases[0].id)
    assert collector.started.wait(timeout=2)
    with pytest.raises(CollectionQueueFullError, match="queue"):
        jobs.start_dns(cases[1].id)

    collector.release.set()
    assert jobs.wait(first.id).status == CollectorStatus.COMPLETE
