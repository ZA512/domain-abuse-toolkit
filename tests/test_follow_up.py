from datetime import UTC, datetime, timedelta

from domain_abuse_toolkit.models import (
    CaseCreate,
    CollectorError,
    CollectorObservation,
    CollectorResult,
    CollectorStatus,
    SnapshotEvent,
    SubmissionEvent,
)
from domain_abuse_toolkit.services.cases import CaseService
from domain_abuse_toolkit.services.drafts import DraftService
from domain_abuse_toolkit.services.evidence import EvidenceStore
from domain_abuse_toolkit.services.follow_up import (
    availability_status,
    next_process_action,
)


def _case(tmp_path):  # type: ignore[no-untyped-def]
    return CaseService(EvidenceStore(tmp_path), DraftService()).create(
        CaseCreate(
            target="https://fraud.example.net/",
            brand="Example Brand",
            legit_url="https://www.example.com/",
        )
    )


def _submission(case_id: str, category: str, occurred_at: datetime, index: int):
    return SubmissionEvent(
        id=f"EVT-{index}",
        case_id=case_id,
        channel_id=f"channel_{index}",
        channel_name=f"Channel {index}",
        channel_category=category,
        occurred_at=occurred_at,
        follow_up_due_at=occurred_at + timedelta(days=7),
    )


def test_standard_process_schedules_j7_then_j14_registry_and_icann(tmp_path) -> None:  # type: ignore[no-untyped-def]
    case = _case(tmp_path)
    start = datetime(2026, 7, 22, 12, tzinfo=UTC)
    now = start + timedelta(days=1)
    case.submissions = [
        _submission(case.id, "registrar_report", start, 1),
        _submission(case.id, "user_protection", start, 2),
    ]

    action = next_process_action(case, now)
    assert action.code == "first_registrar_reminder"
    assert action.due_at == start + timedelta(days=7)
    assert action.overdue is False

    case.submissions.append(
        _submission(case.id, "registrar_report", start + timedelta(days=7), 3)
    )
    assert next_process_action(case, now).due_at == start + timedelta(days=14)
    case.submissions.append(
        _submission(case.id, "registrar_report", start + timedelta(days=14), 4)
    )
    assert next_process_action(case, now).code == "registry_escalation"
    case.submissions.append(
        _submission(case.id, "registry_report", start + timedelta(days=15), 5)
    )
    assert next_process_action(case, now).due_at == start + timedelta(days=21)
    case.submissions.append(
        _submission(case.id, "contractual_escalation", start + timedelta(days=21), 6)
    )
    assert next_process_action(case, now).due_at == start + timedelta(days=30)


def test_availability_uses_http_response_and_treats_failure_as_probable_down(
    tmp_path,
) -> None:  # type: ignore[no-untyped-def]
    case = _case(tmp_path)
    checked = datetime(2026, 7, 22, 12, tzinfo=UTC)
    result = CollectorResult(
        collector="http",
        version="test",
        status=CollectorStatus.COMPLETE,
        started_at=checked,
        finished_at=checked,
        observations=[
            CollectorObservation(category="http", name="hop_0.status", value="200")
        ],
    )
    case.snapshots = [
        SnapshotEvent(
            id="SNP-UP",
            case_id=case.id,
            status=CollectorStatus.COMPLETE,
            started_at=checked,
            finished_at=checked,
            results=[result],
            occurred_at=checked,
        )
    ]

    assert availability_status(case).state == "up"
    assert availability_status(case).http_status == 200

    result.status = CollectorStatus.FAILED
    result.observations = []
    result.errors = [
        CollectorError(code="http_connect_failed", message="failed", retryable=True)
    ]
    assert availability_status(case).state == "down"
