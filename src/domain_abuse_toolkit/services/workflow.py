from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import Any

from domain_abuse_toolkit.models import CaseRecord, CaseState, CollectorStatus


@dataclass(frozen=True)
class WorkflowStep:
    id: str
    label: str
    state: str
    state_label: str
    summary: str
    href: str
    current: bool = False


@dataclass(frozen=True)
class WorkflowView:
    steps: tuple[WorkflowStep, ...]
    current_step_id: str
    next_action_title: str
    next_action_detail: str
    next_action_href: str
    next_action_label: str


def build_case_workflow(
    record: CaseRecord,
    *,
    network_collection_enabled: bool,
    latest_collection_job: Any | None = None,
    collection_error: str | None = None,
    now: datetime | None = None,
    translate: Callable[..., str] | None = None,
) -> WorkflowView:
    """Derive the operator workflow from case facts, never from a second checklist."""

    current_time = now or datetime.now(UTC)
    t = translate or (lambda key, **values: key.format(**values))
    latest_snapshot = record.snapshots[-1] if record.snapshots else None
    latest_submission = record.submissions[-1] if record.submissions else None
    job_status = str(getattr(latest_collection_job, "status", ""))

    evidence_state = "to_do"
    evidence_summary = t("workflow.evidence.none")
    if job_status in {"queued", "running"}:
        evidence_state = "in_progress"
        evidence_summary = t("workflow.evidence.running")
    elif collection_error:
        evidence_state = "attention"
        evidence_summary = t("workflow.evidence.attention")
    elif latest_snapshot is not None:
        evidence_state = (
            "complete"
            if latest_snapshot.status == CollectorStatus.COMPLETE
            else "attention"
        )
        evidence_summary = t("workflow.evidence.count", count=len(record.snapshots))
    elif not network_collection_enabled:
        evidence_summary = t("workflow.evidence.disabled")

    qualification_state = "complete" if record.qualification else "to_do"
    qualification_summary = (
        t("workflow.qualification.confirmed", level=record.criticality_confirmed.value.upper())
        if record.qualification and record.criticality_confirmed
        else t("workflow.qualification.required")
    )

    reporting_state = "complete" if record.submissions else "to_do"
    reporting_summary = (
        t("workflow.reporting.count", count=len(record.submissions))
        if record.submissions
        else t("workflow.reporting.ready")
    )

    follow_up_state = "to_do"
    follow_up_summary = t("workflow.follow_up.waiting")
    if record.state in {
        CaseState.MITIGATED,
        CaseState.CLOSED,
        CaseState.FALSE_POSITIVE,
        CaseState.TRANSFERRED,
    }:
        follow_up_state = "complete"
        follow_up_summary = t("workflow.follow_up.complete")
    elif latest_submission:
        if latest_submission.follow_up_due_at <= current_time:
            follow_up_state = "attention"
            follow_up_summary = t("workflow.follow_up.due")
        else:
            follow_up_state = "scheduled"
            follow_up_summary = t(
                "workflow.follow_up.scheduled",
                date=f"{latest_submission.follow_up_due_at:%Y-%m-%d %H:%M} UTC",
            )

    if job_status in {"queued", "running"} or (
        network_collection_enabled and latest_snapshot is None
    ):
        current_step_id = "evidence"
    elif record.submissions:
        current_step_id = "follow-up"
    elif record.qualification is None:
        current_step_id = "qualification"
    else:
        current_step_id = "reporting"

    steps = (
        _step(
            "overview",
            t("workflow.step.overview"),
            "complete",
            t("workflow.overview.summary"),
            t,
        ),
        _step("evidence", t("workflow.step.evidence"), evidence_state, evidence_summary, t),
        _step(
            "qualification",
            t("workflow.step.qualification"),
            qualification_state,
            qualification_summary, t,
        ),
        _step("reporting", t("workflow.step.reporting"), reporting_state, reporting_summary, t),
        _step("follow-up", t("workflow.step.follow_up"), follow_up_state, follow_up_summary, t),
    )
    steps = tuple(
        replace(step, current=step.id == current_step_id) for step in steps
    )

    next_actions = {
        "evidence": (
            t("workflow.next.evidence.title"),
            evidence_summary,
            "#evidence",
            t("workflow.next.evidence.button"),
        ),
        "qualification": (
            t("workflow.next.qualification.title"),
            qualification_summary,
            "#qualification",
            t("workflow.next.qualification.button"),
        ),
        "reporting": (
            t("workflow.next.reporting.title"),
            t("workflow.next.reporting.detail"),
            "#reporting",
            t("workflow.next.reporting.button"),
        ),
        "follow-up": (
            t("workflow.next.follow_up.title"),
            follow_up_summary,
            "#follow-up",
            t("workflow.next.follow_up.button"),
        ),
    }
    title, detail, href, label = next_actions[current_step_id]
    return WorkflowView(
        steps=steps,
        current_step_id=current_step_id,
        next_action_title=title,
        next_action_detail=detail,
        next_action_href=href,
        next_action_label=label,
    )


def _step(
    step_id: str,
    label: str,
    state: str,
    summary: str,
    translate: Callable[..., str],
) -> WorkflowStep:
    return WorkflowStep(
        id=step_id,
        label=label,
        state=state,
        state_label=translate(f"workflow.state.{state}"),
        summary=summary,
        href=f"#{step_id}",
    )
