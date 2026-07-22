from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from domain_abuse_toolkit.models import CaseRecord, CollectorStatus


@dataclass(frozen=True)
class AvailabilityStatus:
    state: str
    checked_at: datetime | None
    http_status: int | None = None
    detail: str | None = None


@dataclass(frozen=True)
class ProcessAction:
    code: str
    title_key: str
    detail_key: str
    due_at: datetime
    overdue: bool
    phase: str


def availability_status(record: CaseRecord) -> AvailabilityStatus:
    if not record.snapshots:
        return AvailabilityStatus(state="unknown", checked_at=None)
    snapshot = record.snapshots[-1]
    http = next((item for item in snapshot.results if item.collector == "http"), None)
    if http is None:
        return AvailabilityStatus(
            state="unknown", checked_at=snapshot.finished_at, detail="http_not_checked"
        )
    for observation in http.observations:
        if observation.name.endswith(".status"):
            try:
                status = int(observation.value)
            except ValueError:
                continue
            return AvailabilityStatus(
                state="up",
                checked_at=snapshot.finished_at,
                http_status=status,
                detail="http_response",
            )
    if any(error.code == "target_network_blocked" for error in http.errors):
        return AvailabilityStatus(
            state="unknown",
            checked_at=snapshot.finished_at,
            detail="safety_blocked",
        )
    if http.status == CollectorStatus.FAILED or any(
        error.retryable for error in http.errors
    ):
        return AvailabilityStatus(
            state="down", checked_at=snapshot.finished_at, detail="connection_failed"
        )
    return AvailabilityStatus(
        state="unknown", checked_at=snapshot.finished_at, detail="inconclusive"
    )


def next_monitoring_due_at(record: CaseRecord) -> datetime | None:
    if not record.monitoring_enabled or record.monitoring_authorized_at is None:
        return None
    baseline = record.monitoring_authorized_at
    if record.snapshots:
        baseline = max(baseline, record.snapshots[-1].finished_at)
    return baseline + timedelta(hours=record.monitoring_interval_hours)


def next_process_action(record: CaseRecord, now: datetime) -> ProcessAction:
    availability = availability_status(record)
    if availability.state == "down" and availability.checked_at is not None:
        return _action(
            "confirm_mitigation",
            "follow_up.action.confirm_mitigation.title",
            "follow_up.action.confirm_mitigation.detail",
            availability.checked_at,
            now,
            "mitigation",
        )

    registrar = sorted(
        (
            item
            for item in record.submissions
            if item.channel_category == "registrar_report"
        ),
        key=lambda item: item.occurred_at,
    )
    protection = [
        item
        for item in record.submissions
        if item.channel_category == "user_protection"
    ]
    registry = [
        item for item in record.submissions if item.channel_category == "registry_report"
    ]
    icann = [
        item
        for item in record.submissions
        if item.channel_category == "contractual_escalation"
    ]

    if not registrar:
        return _action(
            "initial_registrar",
            "follow_up.action.initial_registrar.title",
            "follow_up.action.initial_registrar.detail",
            record.created_at,
            now,
            "j0",
        )
    start = registrar[0].occurred_at
    if not protection:
        return _action(
            "user_protection",
            "follow_up.action.user_protection.title",
            "follow_up.action.user_protection.detail",
            start,
            now,
            "j0",
        )
    if len(registrar) == 1:
        return _action(
            "first_registrar_reminder",
            "follow_up.action.first_reminder.title",
            "follow_up.action.first_reminder.detail",
            start + timedelta(days=7),
            now,
            "j7",
        )
    if len(registrar) == 2:
        return _action(
            "second_registrar_reminder",
            "follow_up.action.second_reminder.title",
            "follow_up.action.second_reminder.detail",
            start + timedelta(days=14),
            now,
            "j14",
        )
    if not registry:
        return _action(
            "registry_escalation",
            "follow_up.action.registry.title",
            "follow_up.action.registry.detail",
            start + timedelta(days=15),
            now,
            "j15",
        )
    if not icann:
        return _action(
            "icann_escalation",
            "follow_up.action.icann.title",
            "follow_up.action.icann.detail",
            start + timedelta(days=21),
            now,
            "j21",
        )
    return _action(
        "closure_decision",
        "follow_up.action.closure.title",
        "follow_up.action.closure.detail",
        start + timedelta(days=30),
        now,
        "j30",
    )


def _action(
    code: str,
    title_key: str,
    detail_key: str,
    due_at: datetime,
    now: datetime,
    phase: str,
) -> ProcessAction:
    return ProcessAction(
        code=code,
        title_key=title_key,
        detail_key=detail_key,
        due_at=due_at,
        overdue=due_at <= now,
        phase=phase,
    )
