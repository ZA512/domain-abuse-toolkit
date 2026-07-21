from datetime import timedelta

import pytest
from pydantic import ValidationError

from domain_abuse_toolkit.models import (
    CaseCreate,
    CaseState,
    Criticality,
    QualificationSubmission,
    SubmissionCreate,
    Urgency,
)
from domain_abuse_toolkit.services.cases import (
    CaseService,
    QualificationValidationError,
    SubmissionValidationError,
)
from domain_abuse_toolkit.services.drafts import DraftService
from domain_abuse_toolkit.services.evidence import EvidenceStore


def test_case_creation_prepares_actions_drafts_and_manifest(tmp_path) -> None:  # type: ignore[no-untyped-def]
    service = CaseService(EvidenceStore(tmp_path), DraftService())
    case = service.create(
        CaseCreate(
            target="https://login.example.net/account",
            brand="Example Brand",
            legit_url="https://www.example.com/",
            suspicion_type="phishing and credential collection",
            urgency=Urgency.IMMEDIATE,
        )
    )

    assert case.state == CaseState.NEEDS_VALIDATION
    assert case.criticality_proposed == Criticality.CRITICAL
    assert {draft.language for draft in case.drafts} == {"en", "fr"}
    assert any(action.code == "prepare-registrar" for action in case.actions)
    assert service.evidence_store.verify_case(case.id) == []


def test_case_input_rejects_header_control_characters() -> None:
    with pytest.raises(ValidationError):
        CaseCreate(
            target="https://example.net/",
            brand="Example Brand\r\nBcc: attacker@example.net",
            legit_url="https://www.example.com/",
        )


def test_cases_are_restored_from_verified_local_records(tmp_path) -> None:  # type: ignore[no-untyped-def]
    store = EvidenceStore(tmp_path)
    first_service = CaseService(store, DraftService())
    created = first_service.create(
        CaseCreate(
            target="https://login.example.net/account",
            brand="Example Brand",
            legit_url="https://www.example.com/",
        )
    )

    restarted_service = CaseService(EvidenceStore(tmp_path), DraftService())

    assert restarted_service.get(created.id) == created
    assert [case.id for case in restarted_service.list()] == [created.id]
    assert restarted_service.load_warnings == []


def test_action_events_drive_state_and_survive_restart(tmp_path) -> None:  # type: ignore[no-untyped-def]
    service = CaseService(EvidenceStore(tmp_path), DraftService())
    case = service.create(
        CaseCreate(
            target="https://login.example.net/account",
            brand="Example Brand",
            legit_url="https://www.example.com/",
        )
    )

    service.submit_qualification(
        case.id,
        QualificationSubmission(
            brand_represented=True,
            copied_elements=True,
            sensitive_input_or_payment=False,
            victims_or_transactions=False,
            related_case_or_campaign=False,
            publicly_available=True,
            confirmed_criticality=case.criticality_proposed,
            reviewer="MG",
        ),
    )
    assert case.state == CaseState.COLLECTING
    assert case.actions[0].completed_at is not None
    assert case.criticality_confirmed == case.criticality_proposed

    service.set_action_completed(case.id, "prepare-user-protection", completed=True)
    service.set_action_completed(case.id, "prepare-registrar", completed=True)
    assert case.state == CaseState.READY_TO_REPORT
    assert len(service.history(case.id)) == 3

    restarted = CaseService(EvidenceStore(tmp_path), DraftService())
    restored = restarted.get(case.id)
    assert restored.state == CaseState.READY_TO_REPORT
    assert len(restarted.history(case.id)) == 3
    assert restarted.evidence_store.verify_case(case.id) == []

    restarted.set_action_completed(case.id, "prepare-registrar", completed=False)
    assert restored.state == CaseState.COLLECTING
    assert restarted.history(case.id)[0].completed is False


def test_criticality_override_requires_reason_and_revisions_are_audited(
    tmp_path,
) -> None:  # type: ignore[no-untyped-def]
    service = CaseService(EvidenceStore(tmp_path), DraftService())
    case = service.create(
        CaseCreate(
            target="https://shop.example.net/",
            brand="Example Brand",
            legit_url="https://www.example.com/",
        )
    )
    submission = QualificationSubmission(
        brand_represented=True,
        copied_elements=False,
        sensitive_input_or_payment=False,
        victims_or_transactions=False,
        related_case_or_campaign=False,
        publicly_available=True,
        confirmed_criticality=Criticality.LOW,
        reviewer="MG",
    )

    with pytest.raises(QualificationValidationError, match="reason"):
        service.submit_qualification(case.id, submission)

    service.submit_qualification(
        case.id,
        submission.model_copy(update={"override_reason": "No active harmful path observed."}),
    )
    service.submit_qualification(
        case.id,
        submission.model_copy(
            update={
                "confirmed_criticality": case.criticality_proposed,
                "override_reason": "This text is discarded when there is no override.",
            }
        ),
    )

    assert case.qualification is not None
    assert case.qualification.override_reason is None
    assert len(service.history(case.id)) == 2


def test_submission_schedules_follow_up_and_survives_restart(tmp_path) -> None:  # type: ignore[no-untyped-def]
    service = CaseService(EvidenceStore(tmp_path), DraftService())
    case = service.create(
        CaseCreate(
            target="https://login.example.net/account",
            brand="Example Brand",
            legit_url="https://www.example.com/",
            suspicion_type="phishing and credential collection",
        )
    )
    submission = SubmissionCreate(
        channel_id="google_phishing",
        destination="https://safebrowsing.google.com/safebrowsing/report_phish/",
        external_reference="TEST-123",
        confirmed_submitted=True,
    )

    with pytest.raises(SubmissionValidationError, match="Confirm"):
        service.record_submission(
            case.id,
            submission.model_copy(update={"confirmed_submitted": False}),
            channel_name="Google Safe Browsing phishing report",
            channel_category="user_protection",
        )

    service.record_submission(
        case.id,
        submission,
        channel_name="Google Safe Browsing phishing report",
        channel_category="user_protection",
    )

    assert case.state == CaseState.WAITING_EXTERNAL
    assert len(case.submissions) == 1
    assert (
        case.submissions[0].follow_up_due_at - case.submissions[0].occurred_at
        == timedelta(hours=24)
    )
    protection_action = next(
        action for action in case.actions if action.code == "prepare-user-protection"
    )
    assert protection_action.completed_at == case.submissions[0].occurred_at

    restarted = CaseService(EvidenceStore(tmp_path), DraftService())
    restored = restarted.get(case.id)
    assert restored.state == CaseState.WAITING_EXTERNAL
    assert restored.submissions[0].external_reference == "TEST-123"
    assert len(restarted.history(case.id)) == 1
    assert restarted.evidence_store.verify_case(case.id) == []
