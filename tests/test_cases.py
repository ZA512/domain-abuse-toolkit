import pytest
from pydantic import ValidationError

from domain_abuse_toolkit.models import CaseCreate, CaseState, Criticality, Urgency
from domain_abuse_toolkit.services.cases import CaseService
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
