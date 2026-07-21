from datetime import UTC, datetime

from domain_abuse_toolkit.models import (
    CollectorObservation,
    CollectorResult,
    CollectorStatus,
    SnapshotEvent,
)
from domain_abuse_toolkit.services.snapshot_comparison import compare_snapshots


def _result(
    collector: str,
    status: CollectorStatus,
    observations: list[CollectorObservation],
) -> CollectorResult:
    now = datetime.now(UTC)
    return CollectorResult(
        collector=collector,
        version="test",
        status=status,
        started_at=now,
        finished_at=now,
        observations=observations,
    )


def test_snapshot_comparison_groups_values_and_ignores_order_and_ttl() -> None:
    now = datetime.now(UTC)
    previous = SnapshotEvent(
        id="SNP-ONE",
        case_id="DAT-TEST",
        status=CollectorStatus.COMPLETE,
        started_at=now,
        finished_at=now,
        occurred_at=now,
        results=[
            _result(
                "dns",
                CollectorStatus.COMPLETE,
                [
                    CollectorObservation(
                        category="dns",
                        name="example.net",
                        record_type="A",
                        value="8.8.8.8",
                        ttl=60,
                    ),
                    CollectorObservation(
                        category="dns",
                        name="example.net",
                        record_type="A",
                        value="1.1.1.1",
                        ttl=60,
                    ),
                ],
            )
        ],
    )
    current = [
        _result(
            "dns",
            CollectorStatus.COMPLETE,
            [
                CollectorObservation(
                    category="dns",
                    name="example.net",
                    record_type="A",
                    value="1.1.1.1",
                    ttl=300,
                ),
                CollectorObservation(
                    category="dns",
                    name="example.net",
                    record_type="A",
                    value="8.8.8.8",
                    ttl=300,
                ),
            ],
        )
    ]

    assert compare_snapshots(previous, current) == []


def test_snapshot_comparison_reports_grouped_fact_and_collector_status_changes() -> None:
    now = datetime.now(UTC)
    previous = SnapshotEvent(
        id="SNP-ONE",
        case_id="DAT-TEST",
        status=CollectorStatus.COMPLETE,
        started_at=now,
        finished_at=now,
        occurred_at=now,
        results=[
            _result(
                "http",
                CollectorStatus.COMPLETE,
                [
                    CollectorObservation(
                        category="http", name="hop_0.status", value="200"
                    )
                ],
            )
        ],
    )
    changes = compare_snapshots(
        previous,
        [
            _result(
                "http",
                CollectorStatus.PARTIAL,
                [
                    CollectorObservation(
                        category="http", name="hop_0.status", value="404"
                    )
                ],
            )
        ],
    )

    changes_by_key = {(item.category, item.name): item for item in changes}
    assert set(changes_by_key) == {
        ("collector", "status"),
        ("http", "hop_0.status"),
    }
    assert changes_by_key[("collector", "status")].before == ["complete"]
    assert changes_by_key[("collector", "status")].after == ["partial"]
    assert changes_by_key[("http", "hop_0.status")].before == ["200"]
    assert changes_by_key[("http", "hop_0.status")].after == ["404"]
    assert all(item.important for item in changes)
