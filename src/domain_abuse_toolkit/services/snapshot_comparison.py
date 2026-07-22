from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta

from domain_abuse_toolkit.models import (
    CollectorResult,
    Criticality,
    SnapshotChange,
    SnapshotEvent,
)

_REVIEW_HOURS = {
    Criticality.CRITICAL: 24,
    Criticality.HIGH: 168,
    Criticality.CAMPAIGN: 24,
    Criticality.LOW: 168,
}


def next_check_due_at(finished_at: datetime, criticality: Criticality) -> datetime:
    """Return the next operator-triggered technical review date."""
    return finished_at + timedelta(hours=_REVIEW_HOURS[criticality])


def compare_snapshots(
    previous: SnapshotEvent | None, current_results: list[CollectorResult]
) -> list[SnapshotChange]:
    """Compare normalized facts without treating ordering or DNS TTL drift as changes."""
    if previous is None:
        return []

    before = _group_values(previous.results)
    after = _group_values(current_results)
    changes: list[SnapshotChange] = []
    for key in sorted(before.keys() | after.keys()):
        old_values = sorted(before.get(key, set()))
        new_values = sorted(after.get(key, set()))
        if old_values == new_values:
            continue
        collector, category, name, record_type = key
        if not old_values:
            change_type = "added"
        elif not new_values:
            change_type = "removed"
        else:
            change_type = "changed"
        changes.append(
            SnapshotChange(
                collector=collector,
                category=category,
                name=name,
                record_type=record_type or None,
                change_type=change_type,
                before=old_values,
                after=new_values,
                important=_is_important(category, name),
            )
        )
    return sorted(changes, key=lambda item: (not item.important, item.collector, item.name))


def _group_values(
    results: list[CollectorResult],
) -> dict[tuple[str, str, str, str], set[str]]:
    grouped: defaultdict[tuple[str, str, str, str], set[str]] = defaultdict(set)
    for result in results:
        grouped[(result.collector, "collector", "status", "")].add(result.status.value)
        for observation in result.observations:
            grouped[
                (
                    result.collector,
                    observation.category,
                    observation.name,
                    observation.record_type or "",
                )
            ].add(observation.value)
    return dict(grouped)


def _is_important(category: str, name: str) -> bool:
    if category in {"collector", "dns"}:
        return True
    important_markers = {
        "body_sha256",
        "certificate_sha256",
        "document_title",
        "image_sha256",
        "nameserver",
        "peer_address",
        "registrar.abuse_email",
        "registrar.handle",
        "registrar.name",
        "status",
        "url",
    }
    return any(name == marker or name.endswith(f".{marker}") for marker in important_markers)
