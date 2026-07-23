from __future__ import annotations

from domain_abuse_toolkit.models import CollectorStatus, SnapshotEvent

_CORE_COLLECTORS = {"dns", "http", "tls"}


def core_evidence_usable(snapshot: SnapshotEvent) -> bool:
    results = {result.collector: result for result in snapshot.results}
    return all(
        collector in results
        and results[collector].status
        in {CollectorStatus.COMPLETE, CollectorStatus.PARTIAL}
        and bool(results[collector].observations or results[collector].artifacts)
        for collector in _CORE_COLLECTORS
    )


def snapshot_outcome(snapshot: SnapshotEvent) -> str:
    if snapshot.status == CollectorStatus.COMPLETE:
        return "complete"
    if core_evidence_usable(snapshot):
        return "usable_with_limits"
    return "action_required"


def snapshot_can_retry(snapshot: SnapshotEvent) -> bool:
    return any(
        result.status in {CollectorStatus.FAILED, CollectorStatus.SKIPPED}
        or any(error.retryable for error in result.errors)
        for result in snapshot.results
    )
