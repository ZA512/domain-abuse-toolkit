from __future__ import annotations

import json
import threading
import uuid
from datetime import UTC, datetime

from pydantic import ValidationError

from domain_abuse_toolkit.config import Settings
from domain_abuse_toolkit.models import (
    CapabilityStatus,
    CaseCreate,
    CaseRecord,
    CaseState,
    Criticality,
    SuggestedAction,
    Urgency,
)
from domain_abuse_toolkit.security.targets import normalize_target
from domain_abuse_toolkit.services.drafts import DraftService
from domain_abuse_toolkit.services.evidence import EvidenceStore, EvidenceStoreError


class CaseNotFoundError(KeyError):
    pass


class CaseService:
    """Local case service backed by integrity-checked records in the evidence store."""

    def __init__(self, evidence_store: EvidenceStore, drafts: DraftService) -> None:
        self.evidence_store = evidence_store
        self.drafts = drafts
        self._cases: dict[str, CaseRecord] = {}
        self._lock = threading.Lock()
        self.load_warnings: list[str] = []
        self._load_existing_cases()

    def _load_existing_cases(self) -> None:
        for case_id in self.evidence_store.list_case_ids():
            try:
                content = self.evidence_store.read_verified_original(
                    case_id, "00_case/intake.json"
                )
                payload = json.loads(content.decode("utf-8"))
                record = CaseRecord.model_validate(payload["case"])
                if record.id != case_id:
                    raise ValueError("case identifier mismatch")
            except (
                EvidenceStoreError,
                UnicodeDecodeError,
                json.JSONDecodeError,
                KeyError,
                ValidationError,
                ValueError,
            ) as exc:
                self.load_warnings.append(f"{case_id}: {exc}")
                continue
            self._cases[record.id] = record

    @staticmethod
    def preview(intake: CaseCreate) -> tuple[Criticality, list[SuggestedAction]]:
        lowered = intake.suspicion_type.casefold()
        if intake.urgency == Urgency.IMMEDIATE or any(
            marker in lowered for marker in ("credential", "payment", "phishing", "malware")
        ):
            criticality = Criticality.CRITICAL
            follow_up = 24
        elif intake.campaign:
            criticality = Criticality.CAMPAIGN
            follow_up = 72
        elif intake.urgency == Urgency.HIGH:
            criticality = Criticality.HIGH
            follow_up = 72
        else:
            criticality = Criticality.HIGH
            follow_up = 168

        actions = [
            SuggestedAction(
                code="validate-evidence",
                title="Validate the observations and criticality",
                reason="External reports must use human-confirmed facts.",
                due_offset_hours=0,
            ),
            SuggestedAction(
                code="prepare-user-protection",
                title="Prepare user-protection reports",
                reason="Browser and phishing feeds can reduce exposure before takedown.",
                due_offset_hours=0,
            ),
            SuggestedAction(
                code="prepare-registrar",
                title="Prepare the initial registrar report",
                reason="A documented initial report is required for later escalation.",
                due_offset_hours=0,
            ),
            SuggestedAction(
                code="schedule-check",
                title="Schedule a new technical snapshot",
                reason="Availability and infrastructure must be rechecked after reporting.",
                due_offset_hours=follow_up,
            ),
        ]
        return criticality, actions

    def create(self, intake: CaseCreate) -> CaseRecord:
        target = normalize_target(intake.target)
        legit_target = normalize_target(intake.legit_url)
        normalized_intake = intake.model_copy(update={"legit_url": legit_target.normalized_url})
        criticality, actions = self.preview(intake)
        now = datetime.now(UTC)
        case_id = f"DAT-{now:%Y%m%d}-{uuid.uuid4().hex[:8].upper()}"
        record = CaseRecord(
            id=case_id,
            state=CaseState.NEEDS_VALIDATION,
            target=target,
            brand=intake.brand,
            legit_url=legit_target.normalized_url,
            suspicion_type=intake.suspicion_type,
            urgency=intake.urgency,
            campaign=intake.campaign,
            notes=intake.notes,
            criticality_proposed=criticality,
            actions=actions,
            drafts=self.drafts.registrar_drafts(normalized_intake, target),
            created_at=now,
            updated_at=now,
        )
        private_metadata = {
            "schema_version": "1.0",
            "case": record.model_dump(mode="json"),
            "notice": "Local pilot metadata. Do not commit case-data to source control.",
        }
        self.evidence_store.write_original(
            case_id,
            "00_case/intake.json",
            (json.dumps(private_metadata, ensure_ascii=False, indent=2) + "\n").encode(),
            media_type="application/json",
            source="operator intake",
        )
        with self._lock:
            self._cases[case_id] = record
        return record

    def get(self, case_id: str) -> CaseRecord:
        try:
            return self._cases[case_id]
        except KeyError as exc:
            raise CaseNotFoundError(case_id) from exc

    def list(self) -> list[CaseRecord]:
        return sorted(self._cases.values(), key=lambda item: item.created_at, reverse=True)

    @staticmethod
    def capabilities(settings: Settings) -> CapabilityStatus:
        return CapabilityStatus(
            network_collection=settings.enable_network_collection,
            screenshots=settings.enable_screenshots,
            external_apis=settings.enable_external_apis,
            llm=settings.enable_llm,
            microsoft_graph=settings.microsoft_graph_enabled,
        )
