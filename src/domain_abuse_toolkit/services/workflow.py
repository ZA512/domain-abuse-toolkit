from __future__ import annotations

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


_STATE_LABELS = {
    "to_do": "À faire",
    "in_progress": "En cours",
    "complete": "Terminé",
    "attention": "Attention",
    "scheduled": "Planifié",
}


def build_case_workflow(
    record: CaseRecord,
    *,
    network_collection_enabled: bool,
    latest_collection_job: Any | None = None,
    collection_error: str | None = None,
    now: datetime | None = None,
) -> WorkflowView:
    """Derive the operator workflow from case facts, never from a second checklist."""

    current_time = now or datetime.now(UTC)
    latest_snapshot = record.snapshots[-1] if record.snapshots else None
    latest_submission = record.submissions[-1] if record.submissions else None
    job_status = str(getattr(latest_collection_job, "status", ""))

    evidence_state = "to_do"
    evidence_summary = "Aucune collecte technique enregistrée."
    if job_status in {"queued", "running"}:
        evidence_state = "in_progress"
        evidence_summary = "La collecte autorisée est en cours."
    elif collection_error:
        evidence_state = "attention"
        evidence_summary = "La dernière tentative nécessite votre attention."
    elif latest_snapshot is not None:
        evidence_state = (
            "complete"
            if latest_snapshot.status == CollectorStatus.COMPLETE
            else "attention"
        )
        evidence_summary = (
            f"{len(record.snapshots)} relevé(s) technique(s) conservé(s)."
        )
    elif not network_collection_enabled:
        evidence_summary = "Collecte indisponible dans le mode sûr actuel."

    qualification_state = "complete" if record.qualification else "to_do"
    qualification_summary = (
        f"Criticité confirmée : {record.criticality_confirmed.value.upper()}."
        if record.qualification and record.criticality_confirmed
        else "Une validation humaine des observations est requise."
    )

    reporting_state = "complete" if record.submissions else "to_do"
    reporting_summary = (
        f"{len(record.submissions)} signalement(s) externe(s) enregistré(s)."
        if record.submissions
        else "Les canaux et brouillons sont prêts à être examinés."
    )

    follow_up_state = "to_do"
    follow_up_summary = "Le suivi commencera après le premier signalement."
    if record.state in {
        CaseState.MITIGATED,
        CaseState.CLOSED,
        CaseState.FALSE_POSITIVE,
        CaseState.TRANSFERRED,
    }:
        follow_up_state = "complete"
        follow_up_summary = "Le traitement de ce dossier est terminé."
    elif latest_submission:
        if latest_submission.follow_up_due_at <= current_time:
            follow_up_state = "attention"
            follow_up_summary = "Une relance ou un nouveau contrôle est attendu."
        else:
            follow_up_state = "scheduled"
            follow_up_summary = (
                "Prochaine relance le "
                f"{latest_submission.follow_up_due_at:%d/%m/%Y à %H:%M} UTC."
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
        _step("overview", "Dossier", "complete", "Contexte et cible enregistrés."),
        _step("evidence", "Preuves", evidence_state, evidence_summary),
        _step(
            "qualification",
            "Qualification",
            qualification_state,
            qualification_summary,
        ),
        _step("reporting", "Signalements", reporting_state, reporting_summary),
        _step("follow-up", "Suivi", follow_up_state, follow_up_summary),
    )
    steps = tuple(
        replace(step, current=step.id == current_step_id) for step in steps
    )

    next_actions = {
        "evidence": (
            "Constituer les preuves techniques",
            evidence_summary,
            "#evidence",
            "Ouvrir les preuves",
        ),
        "qualification": (
            "Confirmer la qualification",
            qualification_summary,
            "#qualification",
            "Commencer la qualification",
        ),
        "reporting": (
            "Préparer le prochain signalement",
            "Choisissez le canal recommandé, puis utilisez le texte préparé.",
            "#reporting",
            "Préparer le signalement",
        ),
        "follow-up": (
            "Suivre les démarches engagées",
            follow_up_summary,
            "#follow-up",
            "Voir le suivi",
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


def _step(step_id: str, label: str, state: str, summary: str) -> WorkflowStep:
    return WorkflowStep(
        id=step_id,
        label=label,
        state=state,
        state_label=_STATE_LABELS[state],
        summary=summary,
        href=f"#{step_id}",
    )
