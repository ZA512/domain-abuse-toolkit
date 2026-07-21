from __future__ import annotations

import json
import threading
import uuid
from datetime import UTC, datetime, timedelta

from pydantic import ValidationError

from domain_abuse_toolkit.config import Settings
from domain_abuse_toolkit.models import (
    ActionEvent,
    CapabilityStatus,
    CaseCreate,
    CaseRecord,
    CaseState,
    Criticality,
    QualificationEvent,
    QualificationSubmission,
    SnapshotEvent,
    SubmissionCreate,
    SubmissionEvent,
    SuggestedAction,
    Urgency,
)
from domain_abuse_toolkit.security.targets import normalize_target
from domain_abuse_toolkit.services.drafts import DraftService
from domain_abuse_toolkit.services.evidence import (
    EvidenceStore,
    EvidenceStoreError,
    PendingArtifact,
)


class CaseNotFoundError(KeyError):
    pass


class ActionNotFoundError(KeyError):
    pass


class QualificationValidationError(ValueError):
    pass


class SubmissionValidationError(ValueError):
    pass


class CaseService:
    """Local case service backed by integrity-checked records in the evidence store."""

    def __init__(self, evidence_store: EvidenceStore, drafts: DraftService) -> None:
        self.evidence_store = evidence_store
        self.drafts = drafts
        self._cases: dict[str, CaseRecord] = {}
        self._events: dict[
            str, list[ActionEvent | QualificationEvent | SubmissionEvent | SnapshotEvent]
        ] = {}
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
            events: list[
                ActionEvent | QualificationEvent | SubmissionEvent | SnapshotEvent
            ] = []
            try:
                event_paths = self.evidence_store.list_original_paths(
                    case_id, "00_case/events"
                )
            except EvidenceStoreError as exc:
                self.load_warnings.append(f"{case_id}: {exc}")
                event_paths = []

            for event_path in event_paths:
                try:
                    event_content = self.evidence_store.read_verified_original(
                        case_id, event_path
                    )
                    event_payload = json.loads(event_content.decode("utf-8"))
                    raw_event = event_payload["event"]
                    if not isinstance(raw_event, dict):
                        raise ValueError("invalid event payload")
                    if raw_event.get("event_type") == "action_status_changed":
                        event: (
                            ActionEvent
                            | QualificationEvent
                            | SubmissionEvent
                            | SnapshotEvent
                        ) = ActionEvent.model_validate(raw_event)
                    elif raw_event.get("event_type") == "qualification_recorded":
                        event = QualificationEvent.model_validate(raw_event)
                    elif raw_event.get("event_type") == "report_submission_recorded":
                        event = SubmissionEvent.model_validate(raw_event)
                    elif raw_event.get("event_type") == "snapshot_recorded":
                        event = SnapshotEvent.model_validate(raw_event)
                    else:
                        raise ValueError("unknown event type")
                    if event.case_id != case_id:
                        raise ValueError("event case identifier mismatch")
                    if isinstance(event, ActionEvent):
                        self._apply_action_event(record, event)
                    elif isinstance(event, QualificationEvent):
                        self._apply_qualification_event(record, event)
                    elif isinstance(event, SubmissionEvent):
                        self._apply_submission_event(record, event)
                    else:
                        self._apply_snapshot_event(record, event)
                except (
                    EvidenceStoreError,
                    UnicodeDecodeError,
                    json.JSONDecodeError,
                    KeyError,
                    ValidationError,
                    ValueError,
                ) as exc:
                    self.load_warnings.append(f"{case_id}/{event_path}: {exc}")
                    continue
                events.append(event)

            self._cases[record.id] = record
            self._events[record.id] = events

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
            self._events[case_id] = []
        return record

    @staticmethod
    def _apply_action_event(record: CaseRecord, event: ActionEvent) -> None:
        try:
            action = next(item for item in record.actions if item.code == event.action_code)
        except StopIteration as exc:
            raise ValueError(f"unknown action code: {event.action_code}") from exc
        action.completed_at = event.occurred_at if event.completed else None
        record.updated_at = max(record.updated_at, event.occurred_at)
        CaseService._refresh_state(record)

    @staticmethod
    def _apply_qualification_event(
        record: CaseRecord, event: QualificationEvent
    ) -> None:
        record.qualification = event
        record.criticality_confirmed = event.confirmed_criticality
        record.updated_at = max(record.updated_at, event.occurred_at)
        validation_action = next(
            (item for item in record.actions if item.code == "validate-evidence"), None
        )
        if validation_action is not None:
            validation_action.completed_at = event.occurred_at
        CaseService._refresh_state(record)

    @staticmethod
    def _refresh_state(record: CaseRecord) -> None:
        if record.submissions:
            record.state = CaseState.WAITING_EXTERNAL
            return
        required_codes = {
            "validate-evidence",
            "prepare-user-protection",
            "prepare-registrar",
        }
        required_actions = [item for item in record.actions if item.code in required_codes]
        if (
            record.criticality_confirmed is not None
            and required_actions
            and all(item.completed_at for item in required_actions)
        ):
            record.state = CaseState.READY_TO_REPORT
        elif any(item.completed_at for item in record.actions):
            record.state = CaseState.COLLECTING
        else:
            record.state = CaseState.NEEDS_VALIDATION

    def set_action_completed(
        self, case_id: str, action_code: str, *, completed: bool
    ) -> CaseRecord:
        with self._lock:
            try:
                record = self._cases[case_id]
            except KeyError as exc:
                raise CaseNotFoundError(case_id) from exc
            try:
                action = next(item for item in record.actions if item.code == action_code)
            except StopIteration as exc:
                raise ActionNotFoundError(action_code) from exc

            if (action.completed_at is not None) == completed:
                return record

            now = datetime.now(UTC)
            event = ActionEvent(
                id=f"EVT-{uuid.uuid4().hex.upper()}",
                case_id=case_id,
                action_code=action_code,
                completed=completed,
                occurred_at=now,
            )
            payload = {
                "schema_version": "1.0",
                "event": event.model_dump(mode="json"),
                "notice": "Immutable local workflow event.",
            }
            event_path = (
                f"00_case/events/{now:%Y%m%dT%H%M%S.%fZ}-{event.id}.json"
            )
            self.evidence_store.write_original(
                case_id,
                event_path,
                (json.dumps(payload, ensure_ascii=False, indent=2) + "\n").encode(),
                media_type="application/json",
                source="operator workflow action",
            )
            self._apply_action_event(record, event)
            self._events.setdefault(case_id, []).append(event)
            return record

    @staticmethod
    def _apply_submission_event(record: CaseRecord, event: SubmissionEvent) -> None:
        if not any(existing.id == event.id for existing in record.submissions):
            record.submissions.append(event)
        action_code = None
        if event.channel_category in {"user_protection", "authority_report"}:
            action_code = "prepare-user-protection"
        elif event.channel_category == "registrar_report":
            action_code = "prepare-registrar"
        if action_code:
            action = next(
                (item for item in record.actions if item.code == action_code), None
            )
            if action is not None:
                action.completed_at = event.occurred_at
        record.updated_at = max(record.updated_at, event.occurred_at)
        CaseService._refresh_state(record)

    def record_submission(
        self,
        case_id: str,
        submission: SubmissionCreate,
        *,
        channel_name: str,
        channel_category: str,
    ) -> CaseRecord:
        if not submission.confirmed_submitted:
            raise SubmissionValidationError(
                "Confirm that the report was actually submitted before recording it."
            )
        if channel_category == "contact_discovery":
            raise SubmissionValidationError(
                "Contact discovery is not an external report submission."
            )

        with self._lock:
            try:
                record = self._cases[case_id]
            except KeyError as exc:
                raise CaseNotFoundError(case_id) from exc
            now = datetime.now(UTC)
            criticality = record.criticality_confirmed or record.criticality_proposed
            follow_up_hours = {
                Criticality.CRITICAL: 24,
                Criticality.HIGH: 72,
                Criticality.CAMPAIGN: 72,
                Criticality.LOW: 168,
            }[criticality]
            event = SubmissionEvent(
                id=f"EVT-{uuid.uuid4().hex.upper()}",
                case_id=case_id,
                channel_id=submission.channel_id,
                channel_name=channel_name,
                channel_category=channel_category,
                destination=submission.destination,
                external_reference=submission.external_reference,
                notes=submission.notes,
                occurred_at=now,
                follow_up_due_at=now + timedelta(hours=follow_up_hours),
            )
            payload = {
                "schema_version": "1.0",
                "event": event.model_dump(mode="json"),
                "notice": "Immutable operator-confirmed external submission event.",
            }
            event_path = (
                f"00_case/events/{now:%Y%m%dT%H%M%S.%fZ}-{event.id}.json"
            )
            self.evidence_store.write_original(
                case_id,
                event_path,
                (json.dumps(payload, ensure_ascii=False, indent=2) + "\n").encode(),
                media_type="application/json",
                source="operator-confirmed external submission",
            )
            self._apply_submission_event(record, event)
            self._events.setdefault(case_id, []).append(event)
            return record

    @staticmethod
    def _apply_snapshot_event(record: CaseRecord, event: SnapshotEvent) -> None:
        if not any(existing.id == event.id for existing in record.snapshots):
            record.snapshots.append(event)
        record.updated_at = max(record.updated_at, event.occurred_at)

    def record_snapshot(
        self, snapshot: SnapshotEvent, artifacts: list[PendingArtifact]
    ) -> CaseRecord:
        with self._lock:
            try:
                record = self._cases[snapshot.case_id]
            except KeyError as exc:
                raise CaseNotFoundError(snapshot.case_id) from exc
            expected_paths = {
                path for result in snapshot.results for path in result.artifacts
            }
            artifact_paths = {artifact.relative_path for artifact in artifacts}
            if expected_paths != artifact_paths:
                raise ValueError("Snapshot artifact references do not match captured artifacts.")

            for artifact in artifacts:
                self.evidence_store.write_original(
                    snapshot.case_id,
                    artifact.relative_path,
                    artifact.content,
                    media_type=artifact.media_type,
                    source=artifact.source,
                    metadata=artifact.metadata,
                )
            payload = {
                "schema_version": "1.0",
                "event": snapshot.model_dump(mode="json"),
                "notice": "Immutable passive collection snapshot.",
            }
            event_path = (
                f"00_case/events/{snapshot.occurred_at:%Y%m%dT%H%M%S.%fZ}-"
                f"{snapshot.id}.json"
            )
            self.evidence_store.write_original(
                snapshot.case_id,
                event_path,
                (json.dumps(payload, ensure_ascii=False, indent=2) + "\n").encode(),
                media_type="application/json",
                source="passive collection snapshot",
            )
            self._apply_snapshot_event(record, snapshot)
            self._events.setdefault(snapshot.case_id, []).append(snapshot)
            return record

    def submit_qualification(
        self, case_id: str, submission: QualificationSubmission
    ) -> CaseRecord:
        with self._lock:
            try:
                record = self._cases[case_id]
            except KeyError as exc:
                raise CaseNotFoundError(case_id) from exc

            if (
                submission.confirmed_criticality != record.criticality_proposed
                and not submission.override_reason
            ):
                raise QualificationValidationError(
                    "A reason is required when overriding the proposed criticality."
                )

            normalized = submission
            if submission.confirmed_criticality == record.criticality_proposed:
                normalized = submission.model_copy(update={"override_reason": None})

            now = datetime.now(UTC)
            event = QualificationEvent(
                id=f"EVT-{uuid.uuid4().hex.upper()}",
                case_id=case_id,
                occurred_at=now,
                **normalized.model_dump(),
            )
            payload = {
                "schema_version": "1.0",
                "event": event.model_dump(mode="json"),
                "notice": "Immutable local human qualification event.",
            }
            event_path = (
                f"00_case/events/{now:%Y%m%dT%H%M%S.%fZ}-{event.id}.json"
            )
            self.evidence_store.write_original(
                case_id,
                event_path,
                (json.dumps(payload, ensure_ascii=False, indent=2) + "\n").encode(),
                media_type="application/json",
                source="operator qualification",
            )
            self._apply_qualification_event(record, event)
            self._events.setdefault(case_id, []).append(event)
            return record

    def history(
        self, case_id: str
    ) -> list[ActionEvent | QualificationEvent | SubmissionEvent | SnapshotEvent]:
        if case_id not in self._cases:
            raise CaseNotFoundError(case_id)
        return list(reversed(self._events.get(case_id, [])))

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
