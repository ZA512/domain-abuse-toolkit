from datetime import UTC, datetime

from domain_abuse_toolkit.models import (
    CollectorError,
    CollectorObservation,
    CollectorResult,
    CollectorStatus,
    SnapshotEvent,
)
from domain_abuse_toolkit.services.collection_assessment import (
    core_evidence_usable,
    snapshot_can_retry,
    snapshot_outcome,
)


def _result(
    collector: str,
    status: CollectorStatus,
    *,
    error: CollectorError | None = None,
) -> CollectorResult:
    now = datetime.now(UTC)
    return CollectorResult(
        collector=collector,
        version="test",
        status=status,
        started_at=now,
        finished_at=now,
        observations=[
            CollectorObservation(category=collector, name="test", value="present")
        ],
        errors=[error] if error else [],
    )


def _snapshot(results: list[CollectorResult]) -> SnapshotEvent:
    now = datetime.now(UTC)
    return SnapshotEvent(
        id="SNP-ASSESSMENT",
        case_id="DAT-ASSESSMENT",
        status=CollectorStatus.PARTIAL,
        started_at=now,
        finished_at=now,
        results=results,
        occurred_at=now,
    )


def test_partial_snapshot_with_core_evidence_is_usable() -> None:
    snapshot = _snapshot(
        [
            _result("dns", CollectorStatus.COMPLETE),
            _result(
                "http",
                CollectorStatus.PARTIAL,
                error=CollectorError(
                    code="http_body_truncated",
                    message="bounded",
                ),
            ),
            _result("tls", CollectorStatus.COMPLETE),
            _result(
                "rdap",
                CollectorStatus.FAILED,
                error=CollectorError(
                    code="rdap_http_status", message="limited", retryable=True
                ),
            ),
        ]
    )

    assert core_evidence_usable(snapshot)
    assert snapshot_outcome(snapshot) == "usable_with_limits"
    assert snapshot_can_retry(snapshot)


def test_missing_core_evidence_requires_action() -> None:
    snapshot = _snapshot(
        [
            _result("dns", CollectorStatus.COMPLETE),
            _result("http", CollectorStatus.FAILED),
            _result("tls", CollectorStatus.SKIPPED),
        ]
    )

    assert not core_evidence_usable(snapshot)
    assert snapshot_outcome(snapshot) == "action_required"
