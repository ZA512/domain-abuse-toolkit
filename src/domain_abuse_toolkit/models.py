from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field, field_validator


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
