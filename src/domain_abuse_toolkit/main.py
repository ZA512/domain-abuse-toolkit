from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated
from urllib.parse import quote, urlencode

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from domain_abuse_toolkit import __version__
from domain_abuse_toolkit.config import get_settings
from domain_abuse_toolkit.models import ActionUpdate, CaseCreate, Draft, Urgency
from domain_abuse_toolkit.security.targets import TargetValidationError, normalize_target
from domain_abuse_toolkit.services.cases import (
    ActionNotFoundError,
    CaseNotFoundError,
    CaseService,
)
from domain_abuse_toolkit.services.drafts import DraftService
from domain_abuse_toolkit.services.evidence import EvidenceStore

settings = get_settings()
package_root = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=package_root / "resources" / "web_templates")

case_service = CaseService(EvidenceStore(settings.data_dir), DraftService())

app = FastAPI(
    title="Domain Abuse Toolkit",
    version=__version__,
    description="Human-in-the-loop case intake and evidence preparation.",
)
app.mount(
    "/static",
    StaticFiles(directory=package_root / "resources" / "static"),
    name="static",
)


@app.middleware("http")
async def security_headers(request: Request, call_next):  # type: ignore[no-untyped-def]
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        origin = request.headers.get("origin")
        fetch_site = request.headers.get("sec-fetch-site")
        allowed_origins = {
            settings.public_base_url.rstrip("/"),
            f"http://127.0.0.1:{settings.port}",
            f"http://localhost:{settings.port}",
        }
        if fetch_site == "cross-site" or (origin and origin.rstrip("/") not in allowed_origins):
            return PlainTextResponse("Cross-site state change rejected.", status_code=403)
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; "
        "form-action 'self'"
    )
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
    )
    response.headers["Cache-Control"] = "no-store"
    return response


def _mailto(draft: Draft) -> str:
    query = urlencode(
        {"subject": draft.subject, "body": draft.body},
        quote_via=quote,
        safe="",
    )
    return f"mailto:?{query}"


def _case_context(request: Request, case_id: str) -> dict[str, object]:
    try:
        record = case_service.get(case_id)
    except CaseNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Case not found") from exc
    drafts = [{"draft": draft, "mailto": _mailto(draft)} for draft in record.drafts]
    now = datetime.now(UTC)
    actions = []
    for action in record.actions:
        due_at = record.created_at + timedelta(hours=action.due_offset_hours)
        actions.append(
            {
                "action": action,
                "due_at": due_at,
                "overdue": action.completed_at is None and due_at < now,
            }
        )
    action_titles = {action.code: action.title for action in record.actions}
    history = [
        {"event": event, "action_title": action_titles.get(event.action_code, event.action_code)}
        for event in case_service.history(case_id)
    ]
    return {
        "request": request,
        "case": record,
        "drafts": drafts,
        "actions": actions,
        "history": history,
        "capabilities": case_service.capabilities(settings),
        "pilot_notice": True,
    }


def _case_counts(cases: list[object]) -> dict[str, int]:
    return {
        "total": len(cases),
        "critical": sum(case.criticality_proposed.value == "critical" for case in cases),
        "needs_validation": sum(case.state.value == "needs_validation" for case in cases),
    }


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "version": __version__}


@app.get("/", response_class=HTMLResponse)
def home(request: Request):  # type: ignore[no-untyped-def]
    cases = case_service.list()
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "request": request,
            "cases": cases,
            "case_counts": _case_counts(cases),
            "capabilities": case_service.capabilities(settings),
            "load_warnings": case_service.load_warnings,
            "error": None,
            "form": {},
        },
    )


@app.post("/cases", response_class=HTMLResponse)
def create_case_form(
    request: Request,
    target: Annotated[str, Form(max_length=4096)],
    brand: Annotated[str, Form(max_length=200)],
    legit_url: Annotated[str, Form(max_length=4096)],
    suspicion_type: Annotated[str, Form(max_length=200)] = "brand impersonation",
    urgency: Annotated[Urgency, Form()] = Urgency.NORMAL,
    campaign: Annotated[str | None, Form(max_length=200)] = None,
    notes: Annotated[str | None, Form(max_length=4000)] = None,
):  # type: ignore[no-untyped-def]
    intake = CaseCreate(
        target=target,
        brand=brand,
        legit_url=legit_url,
        suspicion_type=suspicion_type,
        urgency=urgency,
        campaign=campaign or None,
        notes=notes or None,
    )
    try:
        record = case_service.create(intake)
    except TargetValidationError as exc:
        cases = case_service.list()
        return templates.TemplateResponse(
            request=request,
            name="index.html",
            context={
                "request": request,
                "cases": cases,
                "case_counts": _case_counts(cases),
                "capabilities": case_service.capabilities(settings),
                "load_warnings": case_service.load_warnings,
                "error": str(exc),
                "form": intake.model_dump(mode="json"),
            },
            status_code=422,
        )
    return RedirectResponse(url=f"/cases/{record.id}", status_code=303)


@app.get("/cases/{case_id}", response_class=HTMLResponse)
def case_detail(request: Request, case_id: str):  # type: ignore[no-untyped-def]
    return templates.TemplateResponse(
        request=request,
        name="case.html",
        context=_case_context(request, case_id),
    )


@app.post("/cases/{case_id}/actions/{action_code}")
def update_action_form(
    case_id: str,
    action_code: str,
    completed: Annotated[bool, Form()],
):  # type: ignore[no-untyped-def]
    try:
        case_service.set_action_completed(case_id, action_code, completed=completed)
    except CaseNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Case not found") from exc
    except ActionNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Action not found") from exc
    return RedirectResponse(url=f"/cases/{case_id}#actions", status_code=303)


@app.post("/api/v1/cases/preview")
def preview_case(intake: CaseCreate) -> dict[str, object]:
    try:
        target = normalize_target(intake.target)
        legitimate = normalize_target(intake.legit_url)
    except TargetValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    criticality, actions = case_service.preview(intake)
    return {
        "target": target.model_dump(mode="json"),
        "legitimate_url": legitimate.normalized_url,
        "criticality_proposed": criticality,
        "actions": [action.model_dump(mode="json") for action in actions],
        "capabilities": case_service.capabilities(settings).model_dump(mode="json"),
        "external_side_effects": False,
    }


@app.post("/api/v1/cases", status_code=201)
def create_case_api(intake: CaseCreate) -> dict[str, object]:
    try:
        record = case_service.create(intake)
    except TargetValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return record.model_dump(mode="json")


@app.get("/api/v1/cases")
def list_cases_api() -> list[dict[str, object]]:
    return [record.model_dump(mode="json") for record in case_service.list()]


@app.get("/api/v1/cases/{case_id}")
def get_case_api(case_id: str) -> dict[str, object]:
    try:
        record = case_service.get(case_id)
    except CaseNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Case not found") from exc
    return record.model_dump(mode="json")


@app.patch("/api/v1/cases/{case_id}/actions/{action_code}")
def update_action_api(
    case_id: str, action_code: str, update: ActionUpdate
) -> dict[str, object]:
    try:
        record = case_service.set_action_completed(
            case_id, action_code, completed=update.completed
        )
    except CaseNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Case not found") from exc
    except ActionNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Action not found") from exc
    return record.model_dump(mode="json")
