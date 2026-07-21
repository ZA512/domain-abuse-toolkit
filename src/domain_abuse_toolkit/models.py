from __future__ import annotations

from datetime import UTC, date, datetime
from enum import StrEnum
from typing import Literal

from pydantic import AnyHttpUrl, BaseModel, Field, field_validator


class CaseState(StrEnum):
    NEW = "new"
    COLLECTING = "collecting"
    NEEDS_VALIDATION = "needs_validation"
    READY_TO_REPORT = "ready_to_report"
    WAITING_EXTERNAL = "waiting_external"
    FOLLOW_UP_DUE = "follow_up_due"
    ESCALATED = "escalated"
    MITIGATED = "mitigated"
    CLOSED = "closed"
    BLOCKED = "blocked"
    TRANSFERRED = "transferred"
    FALSE_POSITIVE = "false_positive"


class Criticality(StrEnum):
    LOW = "low"
    HIGH = "high"
    CRITICAL = "critical"
    CAMPAIGN = "campaign"


class Urgency(StrEnum):
    NORMAL = "normal"
    HIGH = "high"
    IMMEDIATE = "immediate"


class NormalizedTarget(BaseModel):
    exact_input: str
    normalized_url: str
    scheme: str
    host: str
    unicode_host: str
    registrable_domain: str
    port: int | None = None
    path: str
    query: str


class CaseCreate(BaseModel):
    target: str = Field(min_length=1, max_length=4096)
    brand: str = Field(min_length=1, max_length=200)
    legit_url: str = Field(min_length=1, max_length=4096)
    suspicion_type: str = Field(default="brand impersonation", max_length=200)
    urgency: Urgency = Urgency.NORMAL
    campaign: str | None = Field(default=None, max_length=200)
    notes: str | None = Field(default=None, max_length=4000)

    @field_validator("brand", "suspicion_type", "campaign")
    @classmethod
    def validate_single_line_fields(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            raise ValueError("The field must not be blank.")
        if any(ord(character) < 32 or ord(character) == 127 for character in normalized):
            raise ValueError("Single-line fields must not contain control characters.")
        return normalized

    @field_validator("notes")
    @classmethod
    def validate_notes(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if any(ord(character) < 32 and character not in "\r\n\t" for character in value):
            raise ValueError("Notes contain a prohibited control character.")
        return value.strip() or None


class SuggestedAction(BaseModel):
    code: str
    title: str
    reason: str
    due_offset_hours: int = Field(ge=0)
    requires_human_validation: bool = True
    completed_at: datetime | None = None


class ActionEvent(BaseModel):
    id: str
    case_id: str
    event_type: Literal["action_status_changed"] = "action_status_changed"
    action_code: str
    completed: bool
    occurred_at: datetime


class ActionUpdate(BaseModel):
    completed: bool


class QualificationSubmission(BaseModel):
    brand_represented: bool
    copied_elements: bool
    sensitive_input_or_payment: bool
    victims_or_transactions: bool
    related_case_or_campaign: bool
    publicly_available: bool
    confirmed_criticality: Criticality
    reviewer: str = Field(min_length=1, max_length=80)
    override_reason: str | None = Field(default=None, max_length=1000)

    @field_validator("reviewer")
    @classmethod
    def validate_reviewer(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("Reviewer must not be blank.")
        if any(ord(character) < 32 or ord(character) == 127 for character in normalized):
            raise ValueError("Reviewer must not contain control characters.")
        return normalized

    @field_validator("override_reason")
    @classmethod
    def validate_override_reason(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if any(ord(character) < 32 and character not in "\r\n\t" for character in value):
            raise ValueError("Override reason contains a prohibited control character.")
        return value.strip() or None


class QualificationEvent(QualificationSubmission):
    id: str
    case_id: str
    event_type: Literal["qualification_recorded"] = "qualification_recorded"
    occurred_at: datetime


class SubmissionCreate(BaseModel):
    channel_id: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{2,63}$")
    destination: str | None = Field(default=None, max_length=254)
    external_reference: str | None = Field(default=None, max_length=200)
    notes: str | None = Field(default=None, max_length=1000)
    confirmed_submitted: bool = False

    @field_validator("destination", "external_reference")
    @classmethod
    def validate_single_line(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            return None
        if any(ord(character) < 32 or ord(character) == 127 for character in normalized):
            raise ValueError("Submission fields must not contain control characters.")
        return normalized

    @field_validator("notes")
    @classmethod
    def validate_submission_notes(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if any(ord(character) < 32 and character not in "\r\n\t" for character in value):
            raise ValueError("Submission notes contain a prohibited control character.")
        return value.strip() or None


class SubmissionEvent(BaseModel):
    id: str
    case_id: str
    event_type: Literal["report_submission_recorded"] = "report_submission_recorded"
    channel_id: str
    channel_name: str
    channel_category: str
    destination: str | None = None
    external_reference: str | None = None
    notes: str | None = None
    occurred_at: datetime
    follow_up_due_at: datetime


class Draft(BaseModel):
    language: str
    destination_role: str
    subject: str
    body: str
    template_version: str
    missing_placeholders: list[str] = Field(default_factory=list)


class CaseRecord(BaseModel):
    id: str
    state: CaseState
    target: NormalizedTarget
    brand: str
    legit_url: str
    suspicion_type: str
    urgency: Urgency
    campaign: str | None = None
    notes: str | None = None
    criticality_proposed: Criticality
    criticality_confirmed: Criticality | None = None
    qualification: QualificationEvent | None = None
    submissions: list[SubmissionEvent] = Field(default_factory=list)
    actions: list[SuggestedAction]
    drafts: list[Draft]
    created_at: datetime
    updated_at: datetime

    @classmethod
    def now_utc(cls) -> datetime:
        return datetime.now(UTC)


class CapabilityStatus(BaseModel):
    network_collection: bool
    screenshots: bool
    external_apis: bool
    llm: bool
    microsoft_graph: bool


class ReportingChannel(BaseModel):
    id: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{2,63}$")
    name: str
    category: str
    purpose: str
    action_url: AnyHttpUrl
    source_url: AnyHttpUrl
    verified_on: date
    status: Literal["active", "review_needed", "deprecated"]
    required_fields: list[str]
    notes: str

    @field_validator("action_url", "source_url")
    @classmethod
    def validate_official_url(cls, value: AnyHttpUrl) -> AnyHttpUrl:
        if value.scheme != "https" or value.username or value.password:
            raise ValueError("Reporting catalogue URLs must be credential-free HTTPS URLs.")
        return value
