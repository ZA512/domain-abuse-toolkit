from __future__ import annotations

import secrets
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated
from urllib.parse import quote, urlencode, urlsplit

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import ValidationError

from domain_abuse_toolkit import __version__
from domain_abuse_toolkit.config import get_settings
from domain_abuse_toolkit.models import (
    ActionEvent,
    ActionUpdate,
    CaseCreate,
    CaseState,
    CollectionStart,
    CollectorStatus,
    Criticality,
    Draft,
    ManualEvidenceEvent,
    MonitoringEvent,
    MonitoringUpdate,
    QualificationEvent,
    QualificationSubmission,
    SnapshotEvent,
    SubmissionCreate,
    Urgency,
)
from domain_abuse_toolkit.security.targets import TargetValidationError, normalize_target
from domain_abuse_toolkit.services.cases import (
    ActionNotFoundError,
    CaseNotFoundError,
    CaseService,
    ManualEvidenceValidationError,
    QualificationValidationError,
    SubmissionValidationError,
)
from domain_abuse_toolkit.services.collection_assessment import (
    snapshot_can_retry,
    snapshot_outcome,
)
from domain_abuse_toolkit.services.collection_jobs import (
    CollectionAlreadyRunningError,
    CollectionJobService,
    CollectionQueueFullError,
)
from domain_abuse_toolkit.services.collectors import DnsCollector
from domain_abuse_toolkit.services.drafts import DraftService
from domain_abuse_toolkit.services.evidence import EvidenceStore, EvidenceStoreError
from domain_abuse_toolkit.services.exports import EvidenceExportService
from domain_abuse_toolkit.services.follow_up import (
    availability_status,
    next_monitoring_due_at,
    next_process_action,
)
from domain_abuse_toolkit.services.i18n import Translator
from domain_abuse_toolkit.services.monitoring import MonitoringScheduler
from domain_abuse_toolkit.services.rdap_collector import RdapCollector
from domain_abuse_toolkit.services.reporting import (
    ReportingCatalogueError,
    ReportingService,
)
from domain_abuse_toolkit.services.screenshot_collector import ScreenshotCollector
from domain_abuse_toolkit.services.web_collector import (
    BoundedAddressResolver,
    WebCollector,
)
from domain_abuse_toolkit.services.workflow import build_case_workflow

settings = get_settings()
package_root = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=package_root / "resources" / "web_templates")
available_locales = Translator.available_locales()
translators = {locale: Translator(locale) for locale in available_locales}
translator = translators[settings.ui_language]
available_languages = tuple(
    {"code": locale, "name": item("language.self_name")}
    for locale, item in translators.items()
)
templates.env.globals.update(t=translator, ui_language=translator.locale)

draft_service = DraftService()
case_service = CaseService(EvidenceStore(settings.data_dir), draft_service)
export_service = EvidenceExportService(
    case_service.evidence_store,
    max_uncompressed_bytes=settings.max_export_bytes,
)
reporting_service = ReportingService()
collection_jobs = CollectionJobService(
    case_service,
    DnsCollector(
        timeout_seconds=settings.dns_timeout_seconds,
        lifetime_seconds=settings.dns_lifetime_seconds,
        max_records_per_type=settings.max_dns_records_per_type,
    ),
    WebCollector(
        address_resolver=BoundedAddressResolver(
            timeout_seconds=settings.dns_timeout_seconds,
            lifetime_seconds=settings.dns_lifetime_seconds,
        ),
        connect_timeout_seconds=settings.http_connect_timeout_seconds,
        read_timeout_seconds=settings.http_read_timeout_seconds,
        total_timeout_seconds=settings.http_total_timeout_seconds,
        max_redirects=settings.http_max_redirects,
        max_body_bytes=settings.http_max_body_bytes,
    ),
    (
        RdapCollector(
            address_resolver=BoundedAddressResolver(
                timeout_seconds=settings.dns_timeout_seconds,
                lifetime_seconds=settings.dns_lifetime_seconds,
            ),
            connect_timeout_seconds=settings.http_connect_timeout_seconds,
            read_timeout_seconds=settings.http_read_timeout_seconds,
            total_timeout_seconds=settings.http_total_timeout_seconds,
            max_redirects=settings.http_max_redirects,
            max_response_bytes=settings.rdap_max_response_bytes,
            bootstrap_cache_seconds=settings.rdap_bootstrap_cache_seconds,
        )
        if settings.enable_rdap_collection
        else None
    ),
    (
        ScreenshotCollector(
            timeout_seconds=settings.screenshot_timeout_seconds,
            max_input_bytes=settings.screenshot_max_input_bytes,
            max_output_bytes=settings.screenshot_max_output_bytes,
            max_page_height=settings.screenshot_max_page_height,
        )
        if settings.enable_screenshots
        else None
    ),
    max_pending_jobs=settings.max_pending_collection_jobs,
)
monitoring_scheduler = MonitoringScheduler(
    case_service,
    collection_jobs,
    enabled=settings.enable_network_collection,
)
form_csrf_token = secrets.token_urlsafe(32)
language_cookie_name = "dat_ui_language"


@asynccontextmanager
async def lifespan(_app: FastAPI):  # type: ignore[no-untyped-def]
    monitoring_scheduler.start()
    try:
        yield
    finally:
        monitoring_scheduler.stop()


app = FastAPI(
    title="Domain Abuse Toolkit",
    version=__version__,
    description="Human-in-the-loop case intake and evidence preparation.",
    lifespan=lifespan,
)
app.mount(
    "/static",
    StaticFiles(directory=package_root / "resources" / "static"),
    name="static",
)


@app.middleware("http")
async def security_headers(request: Request, call_next):  # type: ignore[no-untyped-def]
    response = None
    if request.url.path.startswith("/api/") and request.method in {
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
    }:
        origin = request.headers.get("origin")
        fetch_site = request.headers.get("sec-fetch-site")
        allowed_origins = {
            settings.public_base_url.rstrip("/"),
            f"http://127.0.0.1:{settings.port}",
            f"http://localhost:{settings.port}",
        }
        if fetch_site == "cross-site" or (origin and origin.rstrip("/") not in allowed_origins):
            response = PlainTextResponse("Cross-site state change rejected.", status_code=403)
    if response is None:
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


def _mailto(draft: Draft, recipient: str = "") -> str:
    query = urlencode(
        {"subject": draft.subject, "body": draft.body},
        quote_via=quote,
        safe="",
    )
    return f"mailto:{quote(recipient, safe='@')}?{query}"


def _verify_form_csrf(token: str) -> None:
    if not token or not secrets.compare_digest(token, form_csrf_token):
        raise HTTPException(
            status_code=403,
            detail="Invalid or expired form token. Refresh the page.",
        )


def _request_translator(request: Request) -> Translator:
    locale = request.cookies.get(language_cookie_name, settings.ui_language)
    return translators.get(locale, translator)


def _ui_context(request: Request) -> dict[str, object]:
    selected = _request_translator(request)
    return {
        "t": selected,
        "ui_language": selected.locale,
        "available_languages": available_languages,
        "language_return_to": request.url.path,
    }


def _safe_return_path(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme or parsed.netloc or not parsed.path.startswith("/"):
        return "/"
    path = parsed.path
    if parsed.query:
        path = f"{path}?{parsed.query}"
    if parsed.fragment:
        path = f"{path}#{parsed.fragment}"
    return path


def _snapshot_assessment(
    snapshot: SnapshotEvent | None,
    *,
    manual_rdap_available: bool = False,
) -> dict[str, object] | None:
    if snapshot is None:
        return None
    results = {result.collector: result for result in snapshot.results}
    sources = []
    for collector in ("dns", "http", "tls", "rdap", "screenshot"):
        result = results.get(collector)
        if result is None:
            continue
        if collector == "rdap" and manual_rdap_available:
            state = "manual"
        else:
            state = {
                CollectorStatus.COMPLETE: "complete",
                CollectorStatus.PARTIAL: "limited",
                CollectorStatus.FAILED: "failed",
                CollectorStatus.SKIPPED: "unavailable",
                CollectorStatus.QUEUED: "unavailable",
                CollectorStatus.RUNNING: "unavailable",
            }[result.status]
        sources.append(
            {
                "collector": collector,
                "state": state,
                "errors": result.errors,
            }
        )
    return {
        "outcome": snapshot_outcome(snapshot),
        "can_retry": snapshot_can_retry(snapshot),
        "sources": sources,
        "limitations": [
            {"collector": result.collector, "error": error}
            for result in snapshot.results
            for error in result.errors
        ],
    }


def _case_context(
    request: Request,
    case_id: str,
    qualification_error: str | None = None,
    submission_error: str | None = None,
    collection_error: str | None = None,
    manual_evidence_error: str | None = None,
    monitoring_error: str | None = None,
) -> dict[str, object]:
    selected_translator = _request_translator(request)
    try:
        record = case_service.get(case_id)
    except CaseNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Case not found") from exc
    registrar_actor = reporting_service.registrar_actor(record)
    registrar_recipient = str(registrar_actor["email"] or "")
    drafts = [
        {"draft": draft, "mailto": _mailto(draft, registrar_recipient)}
        for draft in record.drafts
    ]
    reporting_groups = reporting_service.grouped_channel_views(
        record, selected_translator
    )
    registry_channel = (
        reporting_groups["registry"][0] if reporting_groups["registry"] else None
    )
    registry_drafts: list[dict[str, object]] = []
    if registry_channel:
        channel = registry_channel["channel"]
        recipient = str(channel.recipient_email or "")
        registry_drafts = [
            {"draft": draft, "mailto": _mailto(draft, recipient)}
            for draft in draft_service.registry_drafts(
                record,
                registry_name=channel.name.split(" — ", 1)[0],
                tld=f".{reporting_service.tld(record)}",
            )
        ]
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
    history = []
    for event in case_service.history(case_id):
        if isinstance(event, ActionEvent):
            history.append(
                {
                    "kind": "action",
                    "event": event,
                    "action_title": action_titles.get(event.action_code, event.action_code),
                }
            )
        elif isinstance(event, QualificationEvent):
            history.append({"kind": "qualification", "event": event})
        elif isinstance(event, SnapshotEvent):
            history.append({"kind": "snapshot", "event": event})
        elif isinstance(event, ManualEvidenceEvent):
            history.append({"kind": "manual_evidence", "event": event})
        elif isinstance(event, MonitoringEvent):
            history.append({"kind": "monitoring", "event": event})
        else:
            history.append({"kind": "submission", "event": event})
    integrity_errors = case_service.evidence_store.verify_case(case_id)
    try:
        artifact_count = len(case_service.evidence_store.list_original_paths(case_id))
    except EvidenceStoreError as exc:
        artifact_count = 0
        if str(exc) not in integrity_errors:
            integrity_errors.append(str(exc))
    latest_snapshot = record.snapshots[-1] if record.snapshots else None
    latest_rdap_result = next(
        (
            result
            for result in reversed(latest_snapshot.results)
            if result.collector == "rdap"
        ),
        None,
    ) if latest_snapshot else None
    rdap_manual_needed = bool(
        latest_rdap_result
        and latest_rdap_result.status != CollectorStatus.COMPLETE
    )
    rdap_lookup_url = (
        "https://lookup.icann.org/en/lookup?name="
        f"{quote(record.target.registrable_domain, safe='')}"
    )
    technical_review = None
    if latest_snapshot and latest_snapshot.next_check_due_at:
        technical_review = {
            "due_at": latest_snapshot.next_check_due_at,
            "overdue": latest_snapshot.next_check_due_at <= now,
        }
    latest_collection_job = collection_jobs.latest_for_case(case_id)
    capabilities = case_service.capabilities(settings)
    workflow = build_case_workflow(
        record,
        network_collection_enabled=capabilities.network_collection,
        latest_collection_job=latest_collection_job,
        collection_error=collection_error,
        now=now,
        translate=selected_translator,
    )
    availability = availability_status(record)
    process_action = next_process_action(record, now)
    monitoring_due_at = next_monitoring_due_at(record)
    return {
        "request": request,
        "case": record,
        "drafts": drafts,
        "actions": actions,
        "history": history,
        "criticalities": list(Criticality),
        "qualification_error": qualification_error,
        "submission_error": submission_error,
        "collection_error": collection_error,
        "manual_evidence_error": manual_evidence_error,
        "monitoring_error": monitoring_error,
        "form_csrf_token": form_csrf_token,
        "integrity_errors": integrity_errors,
        "artifact_count": artifact_count,
        "reporting_channels": reporting_service.channel_views(record, selected_translator),
        "reporting_groups": reporting_groups,
        "registrar_actor": registrar_actor,
        "registry_channel": registry_channel,
        "registry_drafts": registry_drafts,
        "tld": reporting_service.tld(record),
        "tld_authority_lookup_url": (
            "https://www.iana.org/domains/root/db/"
            f"{quote(reporting_service.tld(record), safe='')}.html"
        ),
        "reporting_summaries": reporting_service.summaries(record),
        "submission_options": reporting_service.submission_options(record),
        "latest_submission": record.submissions[-1] if record.submissions else None,
        "latest_collection_job": latest_collection_job,
        "latest_snapshot": latest_snapshot,
        "latest_assessment": _snapshot_assessment(
            latest_snapshot,
            manual_rdap_available=bool(record.manual_evidence),
        ),
        "rdap_manual_needed": rdap_manual_needed,
        "rdap_lookup_url": rdap_lookup_url,
        "manual_rdap_evidence": list(reversed(record.manual_evidence)),
        "collection_modal_open": bool(
            latest_collection_job
            and request.query_params.get("collection_job")
            == latest_collection_job.id
        ),
        "technical_review": technical_review,
        "availability": availability,
        "process_action": process_action,
        "monitoring_due_at": monitoring_due_at,
        "snapshots": list(reversed(record.snapshots)),
        "capabilities": capabilities,
        "workflow": workflow,
        "now": now,
        "pilot_notice": True,
        **_ui_context(request),
    }


def _technical_review_status(case: object, now: datetime) -> dict[str, object] | None:
    snapshots = case.snapshots
    if not snapshots or snapshots[-1].next_check_due_at is None:
        return None
    due_at = snapshots[-1].next_check_due_at
    return {"due_at": due_at, "overdue": due_at <= now}


def _display_process_action(case: object, now: datetime):  # type: ignore[no-untyped-def]
    if case.qualification is None or case.state in {
        CaseState.MITIGATED,
        CaseState.CLOSED,
        CaseState.FALSE_POSITIVE,
        CaseState.TRANSFERRED,
    }:
        return None
    return next_process_action(case, now)


def _case_counts(cases: list[object]) -> dict[str, int]:
    now = datetime.now(UTC)
    return {
        "total": len(cases),
        "critical": sum(case.criticality_proposed.value == "critical" for case in cases),
        "needs_validation": sum(case.state.value == "needs_validation" for case in cases),
        "technical_due": sum(
            bool(status and status["overdue"])
            for case in cases
            if (status := _technical_review_status(case, now)) is not None
        ),
        "actions_due": sum(
            bool(action and action.overdue)
            for case in cases
            if (action := _display_process_action(case, now)) is not None
        ),
    }


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "version": __version__}


@app.get("/", response_class=HTMLResponse)
def home(request: Request):  # type: ignore[no-untyped-def]
    cases = case_service.list()
    now = datetime.now(UTC)
    operational_status = {
        case.id: {
            "availability": availability_status(case),
            "next_action": _display_process_action(case, now),
            "monitoring_due_at": next_monitoring_due_at(case),
        }
        for case in cases
    }
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "request": request,
            "cases": cases,
            "case_review_status": {
                case.id: _technical_review_status(case, now) for case in cases
            },
            "case_operational_status": operational_status,
            "case_counts": _case_counts(cases),
            "capabilities": case_service.capabilities(settings),
            "load_warnings": case_service.load_warnings,
            "error": None,
            "form": {},
            "form_csrf_token": form_csrf_token,
            **_ui_context(request),
        },
    )


@app.post("/language")
def change_language(
    locale: Annotated[str, Form(max_length=16)],
    return_to: Annotated[str, Form(max_length=4096)] = "/",
    csrf_token: Annotated[str, Form(alias="_csrf_token")] = "",
) -> RedirectResponse:
    _verify_form_csrf(csrf_token)
    if locale not in translators:
        raise HTTPException(status_code=422, detail="Unsupported interface language.")
    response = RedirectResponse(url=_safe_return_path(return_to), status_code=303)
    response.set_cookie(
        key=language_cookie_name,
        value=locale,
        max_age=365 * 24 * 60 * 60,
        httponly=True,
        samesite="strict",
        path="/",
    )
    return response


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
    csrf_token: Annotated[str, Form(alias="_csrf_token")] = "",
):  # type: ignore[no-untyped-def]
    _verify_form_csrf(csrf_token)
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
        now = datetime.now(UTC)
        operational_status = {
            case.id: {
                "availability": availability_status(case),
                "next_action": _display_process_action(case, now),
                "monitoring_due_at": next_monitoring_due_at(case),
            }
            for case in cases
        }
        return templates.TemplateResponse(
            request=request,
            name="index.html",
            context={
                "request": request,
                "cases": cases,
                "case_review_status": {
                    case.id: _technical_review_status(case, now) for case in cases
                },
                "case_operational_status": operational_status,
                "case_counts": _case_counts(cases),
                "capabilities": case_service.capabilities(settings),
                "load_warnings": case_service.load_warnings,
                "error": str(exc),
                "form": intake.model_dump(mode="json"),
                "form_csrf_token": form_csrf_token,
                **_ui_context(request),
            },
            status_code=422,
        )
    return RedirectResponse(url=f"/cases/{record.id}#evidence", status_code=303)


@app.get("/cases/{case_id}", response_class=HTMLResponse)
def case_detail(
    request: Request,
    case_id: str,
    qualification_error: str | None = None,
    submission_error: str | None = None,
    collection_error: str | None = None,
    manual_evidence_error: str | None = None,
    monitoring_error: str | None = None,
):  # type: ignore[no-untyped-def]
    return templates.TemplateResponse(
        request=request,
        name="case.html",
        context=_case_context(
            request,
            case_id,
            qualification_error,
            submission_error,
            collection_error,
            manual_evidence_error,
            monitoring_error,
        ),
    )


@app.post("/cases/{case_id}/monitoring")
def configure_monitoring_form(
    case_id: str,
    enabled: Annotated[bool, Form()],
    interval_hours: Annotated[int, Form(ge=6, le=168)] = 24,
    confirmed_authorized: Annotated[bool, Form()] = False,
    csrf_token: Annotated[str, Form(alias="_csrf_token")] = "",
) -> RedirectResponse:
    _verify_form_csrf(csrf_token)
    try:
        if enabled and not settings.enable_network_collection:
            raise ValueError("Network collection is disabled in this server process.")
        case_service.configure_monitoring(
            case_id,
            MonitoringUpdate(
                enabled=enabled,
                interval_hours=interval_hours,
                confirmed_authorized=confirmed_authorized,
            ),
        )
        if enabled:
            monitoring_scheduler.poll_once()
    except CaseNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Case not found") from exc
    except (ValidationError, ValueError) as exc:
        if isinstance(exc, ValidationError):
            message = str(exc.errors(include_url=False)[0]["msg"])
        else:
            message = str(exc)
        return RedirectResponse(
            url=(
                f"/cases/{case_id}?monitoring_error={quote(message, safe='')}"
                "#follow-up"
            ),
            status_code=303,
        )
    return RedirectResponse(url=f"/cases/{case_id}#follow-up", status_code=303)


@app.post("/cases/{case_id}/evidence/manual-rdap")
def record_manual_rdap_evidence_form(
    case_id: str,
    content: Annotated[str, Form(min_length=1, max_length=524288)],
    operator: Annotated[str, Form(min_length=1, max_length=80)],
    notes: Annotated[str | None, Form(max_length=1000)] = None,
    csrf_token: Annotated[str, Form(alias="_csrf_token")] = "",
) -> RedirectResponse:
    _verify_form_csrf(csrf_token)
    try:
        record = case_service.get(case_id)
        source_url = (
            "https://lookup.icann.org/en/lookup?name="
            f"{quote(record.target.registrable_domain, safe='')}"
        )
        case_service.record_manual_rdap_evidence(
            case_id,
            content=content,
            operator=operator,
            source_url=source_url,
            notes=notes,
        )
    except CaseNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Case not found") from exc
    except ManualEvidenceValidationError as exc:
        encoded_error = quote(str(exc), safe="")
        return RedirectResponse(
            url=(
                f"/cases/{case_id}?manual_evidence_error={encoded_error}"
                "#manual-rdap"
            ),
            status_code=303,
        )
    return RedirectResponse(url=f"/cases/{case_id}#manual-rdap", status_code=303)


@app.get("/cases/{case_id}/snapshots/{snapshot_id}/capture.png")
def view_snapshot_capture(case_id: str, snapshot_id: str) -> Response:
    try:
        record = case_service.get(case_id)
    except CaseNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Case not found") from exc
    snapshot = next(
        (item for item in record.snapshots if item.id == snapshot_id), None
    )
    if snapshot is None:
        raise HTTPException(status_code=404, detail="Snapshot not found")
    expected_path = f"10_snapshots/{snapshot_id}/capture/desktop.png"
    if not any(
        result.collector == "screenshot" and expected_path in result.artifacts
        for result in snapshot.results
    ):
        raise HTTPException(status_code=404, detail="Capture not found")
    try:
        content = case_service.evidence_store.read_verified_artifact(
            case_id, expected_path
        )
    except EvidenceStoreError as exc:
        raise HTTPException(status_code=409, detail="Capture integrity check failed") from exc
    return Response(
        content=content,
        media_type="image/png",
        headers={
            "Cache-Control": "no-store",
            "Content-Disposition": f'inline; filename="{snapshot_id}-desktop.png"',
        },
    )


@app.get("/cases/{case_id}/evidence.zip")
def download_evidence(case_id: str) -> Response:
    try:
        case_service.get(case_id)
        archive = export_service.build(case_id)
    except CaseNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Case not found") from exc
    except EvidenceStoreError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return Response(
        content=archive.content,
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="{case_id}-evidence.zip"',
            "X-Evidence-Archive-SHA256": archive.sha256,
            "X-Evidence-Manifest-SHA256": archive.manifest_sha256,
            "X-Evidence-Artifact-Count": str(archive.artifact_count),
        },
    )


@app.post("/cases/{case_id}/qualification")
def submit_qualification_form(
    case_id: str,
    confirmed_criticality: Annotated[Criticality, Form()],
    reviewer: Annotated[str, Form(min_length=1, max_length=80)],
    brand_represented: Annotated[bool, Form()] = False,
    copied_elements: Annotated[bool, Form()] = False,
    sensitive_input_or_payment: Annotated[bool, Form()] = False,
    victims_or_transactions: Annotated[bool, Form()] = False,
    related_case_or_campaign: Annotated[bool, Form()] = False,
    publicly_available: Annotated[bool, Form()] = False,
    override_reason: Annotated[str | None, Form(max_length=1000)] = None,
    csrf_token: Annotated[str, Form(alias="_csrf_token")] = "",
):  # type: ignore[no-untyped-def]
    _verify_form_csrf(csrf_token)
    try:
        submission = QualificationSubmission(
            brand_represented=brand_represented,
            copied_elements=copied_elements,
            sensitive_input_or_payment=sensitive_input_or_payment,
            victims_or_transactions=victims_or_transactions,
            related_case_or_campaign=related_case_or_campaign,
            publicly_available=publicly_available,
            confirmed_criticality=confirmed_criticality,
            reviewer=reviewer,
            override_reason=override_reason,
        )
    except ValidationError as exc:
        message = exc.errors(include_url=False)[0]["msg"]
        encoded_error = quote(str(message), safe="")
        return RedirectResponse(
            url=f"/cases/{case_id}?qualification_error={encoded_error}#qualification",
            status_code=303,
        )
    try:
        case_service.submit_qualification(case_id, submission)
    except CaseNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Case not found") from exc
    except QualificationValidationError as exc:
        encoded_error = quote(str(exc), safe="")
        return RedirectResponse(
            url=f"/cases/{case_id}?qualification_error={encoded_error}#qualification",
            status_code=303,
        )
    return RedirectResponse(url=f"/cases/{case_id}#reporting", status_code=303)


@app.post("/cases/{case_id}/submissions")
def record_submission_form(
    case_id: str,
    channel_id: Annotated[str, Form(max_length=64)],
    destination: Annotated[str | None, Form(max_length=254)] = None,
    external_reference: Annotated[str | None, Form(max_length=200)] = None,
    notes: Annotated[str | None, Form(max_length=1000)] = None,
    confirmed_submitted: Annotated[bool, Form()] = False,
    csrf_token: Annotated[str, Form(alias="_csrf_token")] = "",
):  # type: ignore[no-untyped-def]
    _verify_form_csrf(csrf_token)
    try:
        submission = SubmissionCreate(
            channel_id=channel_id,
            destination=destination,
            external_reference=external_reference,
            notes=notes,
            confirmed_submitted=confirmed_submitted,
        )
        record = case_service.get(case_id)
        channel = reporting_service.resolve_submission_channel(channel_id, record)
        case_service.record_submission(
            case_id,
            submission,
            channel_name=channel["name"],
            channel_category=channel["category"],
        )
    except CaseNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Case not found") from exc
    except (ValidationError, ReportingCatalogueError, SubmissionValidationError) as exc:
        if isinstance(exc, ValidationError):
            message = str(exc.errors(include_url=False)[0]["msg"])
        else:
            message = str(exc)
        encoded_error = quote(message, safe="")
        return RedirectResponse(
            url=f"/cases/{case_id}?submission_error={encoded_error}#reporting",
            status_code=303,
        )
    return RedirectResponse(url=f"/cases/{case_id}#follow-up", status_code=303)


@app.post("/cases/{case_id}/collections/dns")
def start_dns_collection_form(
    case_id: str,
    confirmed_authorized: Annotated[bool, Form()] = False,
    csrf_token: Annotated[str, Form(alias="_csrf_token")] = "",
):  # type: ignore[no-untyped-def]
    _verify_form_csrf(csrf_token)
    try:
        job = _start_dns_collection(
            case_id, confirmed_authorized=confirmed_authorized
        )
    except CaseNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Case not found") from exc
    except ValueError as exc:
        encoded_error = quote(str(exc), safe="")
        return RedirectResponse(
            url=f"/cases/{case_id}?collection_error={encoded_error}#evidence",
            status_code=303,
        )
    return RedirectResponse(
        url=f"/cases/{case_id}?collection_job={job.id}#evidence", status_code=303
    )


def _start_dns_collection(case_id: str, *, confirmed_authorized: bool):  # type: ignore[no-untyped-def]
    if not settings.enable_network_collection:
        raise ValueError("Network collection is disabled in this server process.")
    if not confirmed_authorized:
        raise ValueError("Confirm authorization before starting passive collection.")
    return collection_jobs.start_dns(case_id)


@app.post("/cases/{case_id}/collections/passive")
def start_passive_collection_form(
    case_id: str,
    confirmed_authorized: Annotated[bool, Form()] = False,
    csrf_token: Annotated[str, Form(alias="_csrf_token")] = "",
):  # type: ignore[no-untyped-def]
    _verify_form_csrf(csrf_token)
    try:
        job = _start_passive_collection(
            case_id, confirmed_authorized=confirmed_authorized
        )
    except CaseNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Case not found") from exc
    except ValueError as exc:
        encoded_error = quote(str(exc), safe="")
        return RedirectResponse(
            url=f"/cases/{case_id}?collection_error={encoded_error}#evidence",
            status_code=303,
        )
    return RedirectResponse(
        url=f"/cases/{case_id}?collection_job={job.id}#evidence", status_code=303
    )


def _start_passive_collection(
    case_id: str, *, confirmed_authorized: bool
):  # type: ignore[no-untyped-def]
    if not settings.enable_network_collection:
        raise ValueError("Network collection is disabled in this server process.")
    if not confirmed_authorized:
        raise ValueError("Confirm authorization before starting passive collection.")
    return collection_jobs.start_passive(case_id)


@app.post("/cases/{case_id}/actions/{action_code}")
def update_action_form(
    case_id: str,
    action_code: str,
    completed: Annotated[bool, Form()],
    csrf_token: Annotated[str, Form(alias="_csrf_token")] = "",
):  # type: ignore[no-untyped-def]
    _verify_form_csrf(csrf_token)
    try:
        case_service.set_action_completed(case_id, action_code, completed=completed)
    except CaseNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Case not found") from exc
    except ActionNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Action not found") from exc
    return RedirectResponse(url=f"/cases/{case_id}#follow-up", status_code=303)


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


@app.get("/api/v1/cases/{case_id}/collections/latest")
def latest_collection_api(case_id: str) -> dict[str, object]:
    try:
        record = case_service.get(case_id)
    except CaseNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Case not found") from exc
    job = collection_jobs.latest_for_case(case_id)
    if job is None:
        raise HTTPException(status_code=404, detail="No collection job found")
    snapshot = next(
        (item for item in record.snapshots if item.id == job.snapshot_id), None
    )
    return {
        "job": job.model_dump(mode="json"),
        "terminal": job.status
        not in {CollectorStatus.QUEUED, CollectorStatus.RUNNING},
        "outcome": snapshot_outcome(snapshot) if snapshot else None,
        "results": (
            [
                {
                    "collector": result.collector,
                    "status": result.status,
                    "errors": [error.model_dump() for error in result.errors],
                }
                for result in snapshot.results
            ]
            if snapshot
            else []
        ),
    }


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


@app.post("/api/v1/cases/{case_id}/qualification")
def submit_qualification_api(
    case_id: str, submission: QualificationSubmission
) -> dict[str, object]:
    try:
        record = case_service.submit_qualification(case_id, submission)
    except CaseNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Case not found") from exc
    except QualificationValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return record.model_dump(mode="json")


@app.post("/api/v1/cases/{case_id}/submissions", status_code=201)
def record_submission_api(
    case_id: str, submission: SubmissionCreate
) -> dict[str, object]:
    try:
        existing = case_service.get(case_id)
        channel = reporting_service.resolve_submission_channel(
            submission.channel_id, existing
        )
        record = case_service.record_submission(
            case_id,
            submission,
            channel_name=channel["name"],
            channel_category=channel["category"],
        )
    except CaseNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Case not found") from exc
    except (ReportingCatalogueError, SubmissionValidationError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return record.model_dump(mode="json")


@app.post("/api/v1/cases/{case_id}/collections/dns", status_code=202)
def start_dns_collection_api(
    case_id: str, request: CollectionStart
) -> dict[str, object]:
    try:
        job = _start_dns_collection(
            case_id, confirmed_authorized=request.confirmed_authorized
        )
    except CaseNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Case not found") from exc
    except (CollectionAlreadyRunningError, CollectionQueueFullError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    return job.model_dump(mode="json")


@app.post("/api/v1/cases/{case_id}/collections/passive", status_code=202)
def start_passive_collection_api(
    case_id: str, request: CollectionStart
) -> dict[str, object]:
    try:
        job = _start_passive_collection(
            case_id, confirmed_authorized=request.confirmed_authorized
        )
    except CaseNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Case not found") from exc
    except (CollectionAlreadyRunningError, CollectionQueueFullError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    return job.model_dump(mode="json")
