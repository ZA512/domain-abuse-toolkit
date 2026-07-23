import importlib
import io
import re
from datetime import UTC, datetime, timedelta
from zipfile import ZipFile

import pytest
from fastapi.testclient import TestClient

from domain_abuse_toolkit.config import get_settings
from domain_abuse_toolkit.models import (
    CollectorResult,
    CollectorStatus,
    SnapshotChange,
    SnapshotEvent,
)
from domain_abuse_toolkit.services.collection_jobs import CollectionJobView
from domain_abuse_toolkit.services.evidence import PendingArtifact


def _csrf_token(client: TestClient, path: str = "/") -> str:
    response = client.get(path)
    match = re.search(r'name="_csrf_token" value="([^"]+)"', response.text)
    assert match is not None
    return match.group(1)


@pytest.fixture
def client(tmp_path, monkeypatch) -> TestClient:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("DAT_DATA_DIR", str(tmp_path / "case-data"))
    get_settings.cache_clear()
    main_module = importlib.import_module("domain_abuse_toolkit.main")
    main_module = importlib.reload(main_module)
    return TestClient(main_module.app)


def test_health_and_home(client: TestClient) -> None:
    health = client.get("/health")
    assert health.status_code == 200
    assert health.json()["status"] == "ok"

    home = client.get("/")
    assert home.status_code == 200
    assert "What needs attention now?" in home.text
    assert home.text.index('class="panel work-queue"') < home.text.index(
        'id="new-case"'
    )
    assert 'data-case-search' in home.text
    assert '<select id="ui-language" name="locale"' in home.text
    assert "English" in home.text and "Français" in home.text
    assert home.headers["x-frame-options"] == "DENY"


def test_language_can_be_changed_from_the_web_interface(client: TestClient) -> None:
    csrf_token = _csrf_token(client)

    changed = client.post(
        "/language",
        data={
            "_csrf_token": csrf_token,
            "locale": "fr",
            "return_to": "/#reporting",
        },
        follow_redirects=False,
    )

    assert changed.status_code == 303
    assert changed.headers["location"] == "/#reporting"
    assert "dat_ui_language=fr" in changed.headers["set-cookie"]
    french = client.get("/")
    assert '<html lang="fr">' in french.text
    assert "Que faut-il traiter maintenant" in french.text
    assert "Copié" in french.text


def test_case_can_be_closed_and_reopened_from_the_web_interface(
    client: TestClient,
) -> None:
    created = client.post(
        "/api/v1/cases",
        json={
            "target": "https://test.example.net/",
            "brand": "Test Brand",
            "legit_url": "https://www.example.com/",
        },
    ).json()
    case_path = f"/cases/{created['id']}"

    detail = client.get(case_path)
    assert "Manage case" in detail.text
    assert "Close case" in detail.text

    closed = client.post(
        f"{case_path}/lifecycle",
        data={
            "_csrf_token": _csrf_token(client, case_path),
            "action": "close",
            "resolution": "closed",
            "operator": "MG",
            "reason": "Test case created during validation.",
        },
        follow_redirects=False,
    )
    assert closed.status_code == 303
    assert closed.headers["location"] == f"{case_path}#case-management"

    closed_detail = client.get(case_path)
    assert "This case remains readable and exportable" in closed_detail.text
    assert "Reopen case" in closed_detail.text
    assert "No operational action is expected" in closed_detail.text
    assert 'data-default-step="overview"' in closed_detail.text
    home = client.get("/")
    assert "Closed cases" in home.text
    assert created["id"] in home.text

    reopened = client.post(
        f"{case_path}/lifecycle",
        data={
            "_csrf_token": _csrf_token(client, case_path),
            "action": "reopen",
            "operator": "MG",
            "reason": "Continue operational validation.",
        },
        follow_redirects=False,
    )
    assert reopened.status_code == 303
    reopened_detail = client.get(case_path)
    assert "Close case" in reopened_detail.text
    assert "Case reopened" in reopened_detail.text


def test_language_change_rejects_invalid_input_and_external_redirects(
    client: TestClient,
) -> None:
    csrf_token = _csrf_token(client)
    unsupported = client.post(
        "/language",
        data={"_csrf_token": csrf_token, "locale": "xx", "return_to": "/"},
        follow_redirects=False,
    )
    safe_redirect = client.post(
        "/language",
        data={
            "_csrf_token": csrf_token,
            "locale": "en",
            "return_to": "https://attacker.example/",
        },
        follow_redirects=False,
    )

    assert unsupported.status_code == 422
    assert safe_redirect.status_code == 303
    assert safe_redirect.headers["location"] == "/"


def test_dns_collection_is_disabled_by_default_and_requires_opt_in(
    client: TestClient,
) -> None:
    created = client.post(
        "/api/v1/cases",
        json={
            "target": "https://login.example.net/",
            "brand": "Example Brand",
            "legit_url": "https://www.example.com/",
        },
    ).json()

    rejected = client.post(
        f"/api/v1/cases/{created['id']}/collections/dns",
        json={"confirmed_authorized": True},
    )
    assert rejected.status_code == 403
    assert "disabled" in rejected.json()["detail"]

    passive_rejected = client.post(
        f"/api/v1/cases/{created['id']}/collections/passive",
        json={"confirmed_authorized": True},
    )
    assert passive_rejected.status_code == 403

    detail = client.get(f"/cases/{created['id']}")
    assert "Opening a case never contacts the target" in detail.text
    assert "Technical collection is disabled in safe mode" in detail.text
    assert 'data-default-step="qualification"' in detail.text
    assert detail.text.count("data-workflow-step=") == 5
    assert "Confirm qualification" in detail.text


def test_passive_collection_opens_live_progress_dialog(client: TestClient) -> None:
    created = client.post(
        "/api/v1/cases",
        json={
            "target": "https://example.net/",
            "brand": "Example Brand",
            "legit_url": "https://www.example.com/",
        },
    ).json()
    main_module = importlib.import_module("domain_abuse_toolkit.main")
    now = datetime.now(UTC)
    job = CollectionJobView(
        id="JOB-LIVE-PROGRESS",
        case_id=created["id"],
        snapshot_id="SNP-LIVE-PROGRESS",
        status=CollectorStatus.RUNNING,
        queued_at=now,
        started_at=now,
        current_stage="http_tls",
        planned_stages=["dns", "http_tls", "rdap", "screenshot", "persisting"],
        completed_stages=["dns"],
    )

    class FakeJobs:
        @staticmethod
        def start_passive(_case_id: str) -> CollectionJobView:
            return job

        @staticmethod
        def latest_for_case(_case_id: str) -> CollectionJobView:
            return job

    main_module.collection_jobs = FakeJobs()
    main_module.settings.enable_network_collection = True
    case_path = f"/cases/{created['id']}"
    started = client.post(
        f"{case_path}/collections/passive",
        data={
            "_csrf_token": _csrf_token(client, case_path),
            "confirmed_authorized": "true",
        },
        follow_redirects=False,
    )

    assert started.status_code == 303
    assert "collection_job=JOB-LIVE-PROGRESS" in started.headers["location"]
    progress_page = client.get(
        f"{case_path}?collection_job=JOB-LIVE-PROGRESS"
    )
    assert 'data-auto-open="true"' in progress_page.text
    assert 'data-collection-stage="http_tls"' in progress_page.text
    status = client.get(f"/api/v1/cases/{created['id']}/collections/latest")
    assert status.status_code == 200
    assert status.json()["job"]["current_stage"] == "http_tls"
    assert not status.json()["terminal"]
    script = client.get("/static/app.js")
    assert "clearCollectionJobFromUrl" in script.text
    assert 'currentUrl.searchParams.delete("collection_job")' in script.text


def test_rdap_limitation_offers_manual_evidence_capture(client: TestClient) -> None:
    created = client.post(
        "/api/v1/cases",
        json={
            "target": "https://login.example.net/",
            "brand": "Example Brand",
            "legit_url": "https://www.example.com/",
        },
    ).json()
    main_module = importlib.import_module("domain_abuse_toolkit.main")
    now = datetime.now(UTC)
    main_module.case_service.record_snapshot(
        SnapshotEvent(
            id="SNP-RDAP-LIMITED",
            case_id=created["id"],
            status=CollectorStatus.PARTIAL,
            started_at=now,
            finished_at=now,
            occurred_at=now,
            results=[
                CollectorResult(
                    collector="dns",
                    version="test",
                    status=CollectorStatus.COMPLETE,
                    started_at=now,
                    finished_at=now,
                    observations=[
                        {"category": "dns", "name": "A", "value": "192.0.2.1"}
                    ],
                ),
                CollectorResult(
                    collector="http",
                    version="test",
                    status=CollectorStatus.PARTIAL,
                    started_at=now,
                    finished_at=now,
                    observations=[
                        {"category": "http", "name": "status", "value": "200"}
                    ],
                    errors=[
                        {
                            "code": "http_body_truncated",
                            "message": "bounded",
                            "retryable": False,
                        }
                    ],
                ),
                CollectorResult(
                    collector="tls",
                    version="test",
                    status=CollectorStatus.COMPLETE,
                    started_at=now,
                    finished_at=now,
                    observations=[
                        {"category": "tls", "name": "protocol", "value": "TLSv1.3"}
                    ],
                ),
                CollectorResult(
                    collector="rdap",
                    version="test",
                    status=CollectorStatus.FAILED,
                    started_at=now,
                    finished_at=now,
                    observations=[
                        {
                            "category": "rdap",
                            "name": "query_url",
                            "value": "https://rdap.example/rdap/domain/example.net",
                        }
                    ],
                    errors=[
                        {
                            "code": "rdap_http_status",
                            "message": "HTTP 429",
                            "retryable": True,
                        }
                    ],
                ),
                CollectorResult(
                    collector="screenshot",
                    version="test",
                    status=CollectorStatus.COMPLETE,
                    started_at=now,
                    finished_at=now,
                    observations=[
                        {"category": "capture", "name": "mode", "value": "offline"}
                    ],
                ),
            ],
        ),
        [],
    )
    case_path = f"/cases/{created['id']}"

    page = client.get(case_path)
    assert "RDAP unavailable in the latest collection" in page.text
    assert "Expand this card for the manual procedure" in page.text
    assert 'class="manual-evidence"' in page.text
    assert 'class="manual-evidence" open' not in page.text
    assert "Latest collection" in page.text
    assert "Technical evidence recorded." in page.text
    assert "evidence-source evidence-source-complete" in page.text
    assert "evidence-source evidence-source-limited" in page.text
    assert "evidence-source evidence-source-failed" in page.text
    assert re.search(
        r'data-workflow-step="evidence"[\s\S]*?class="workflow-marker"[^>]*>✓</span>',
        page.text,
    )
    assert "https://lookup.icann.org/en/lookup?name=example.net" in page.text
    assert "https://rdap.example/rdap/domain/example.net" in page.text
    assert "Open authoritative RDAP server" in page.text
    assert "raw RDAP response is available at the bottom" in page.text

    saved = client.post(
        f"{case_path}/evidence/manual-rdap",
        data={
            "_csrf_token": _csrf_token(client, case_path),
            "content": "Registrar: Example Registrar\nAbuse: abuse@example.test",
            "operator": "MG",
            "notes": "Copied manually",
        },
        follow_redirects=False,
    )
    assert saved.status_code == 303
    assert saved.headers["location"] == f"{case_path}#manual-rdap"

    updated = client.get(case_path)
    assert "Manual evidence recorded" in updated.text
    assert "Added by MG" in updated.text
    assert "RDAP completed manually" in updated.text
    assert "evidence-source evidence-source-manual" in updated.text
    event = main_module.case_service.get(created["id"]).manual_evidence[0]
    assert main_module.case_service.evidence_store.read_verified_original(
        created["id"], event.artifact_path
    ).startswith(b"Registrar: Example Registrar")


def test_collection_dialog_does_not_confuse_collector_error_with_save_failure(
    client: TestClient,
) -> None:
    script = client.get("/static/app.js")
    assert script.status_code == 200
    assert 'completed_stages.includes("persisting") ? "complete" : "failed"' in script.text
    assert 'payload.job.error ? "failed" : "complete"' not in script.text
    assert '"manual-rdap": "evidence"' in script.text
    assert "window.location.replace(finishLink.href)" in script.text


def test_verified_capture_is_displayed_inline_and_tampering_is_rejected(
    client: TestClient,
) -> None:
    created = client.post(
        "/api/v1/cases",
        json={
            "target": "https://example.com/",
            "brand": "Example Brand",
            "legit_url": "https://www.example.com/",
        },
    ).json()
    main_module = importlib.import_module("domain_abuse_toolkit.main")
    now = datetime.now(UTC)
    snapshot_id = "SNP-CAPTURE-TEST"
    source_path = f"10_snapshots/{snapshot_id}/http/00-body.bin"
    capture_path = f"10_snapshots/{snapshot_id}/capture/desktop.png"
    main_module.case_service.record_snapshot(
        SnapshotEvent(
            id=snapshot_id,
            case_id=created["id"],
            status=CollectorStatus.COMPLETE,
            started_at=now,
            finished_at=now,
            occurred_at=now,
            results=[
                CollectorResult(
                    collector="http",
                    version="test",
                    status=CollectorStatus.COMPLETE,
                    started_at=now,
                    finished_at=now,
                    artifacts=[source_path],
                ),
                CollectorResult(
                    collector="screenshot",
                    version="test",
                    status=CollectorStatus.COMPLETE,
                    started_at=now,
                    finished_at=now,
                    artifacts=[capture_path],
                ),
            ],
        ),
        [
            PendingArtifact(
                relative_path=source_path,
                content=b"<h1>synthetic</h1>",
                media_type="text/html",
                source="synthetic HTTP evidence",
            ),
            PendingArtifact(
                relative_path=capture_path,
                content=b"\x89PNG\r\n\x1a\nsynthetic",
                media_type="image/png",
                source="synthetic offline rendering",
                classification="derived",
                derived_from=(source_path,),
            ),
        ],
    )

    route = f"/cases/{created['id']}/snapshots/{snapshot_id}/capture.png"
    detail = client.get(f"/cases/{created['id']}")
    capture = client.get(route)

    assert route in detail.text
    assert capture.status_code == 200
    assert capture.headers["content-type"] == "image/png"
    assert capture.headers["cache-control"] == "no-store"

    evidence_root = main_module.case_service.evidence_store.root
    (evidence_root / created["id"] / capture_path).write_bytes(b"tampered")
    assert client.get(route).status_code == 409


def test_snapshot_changes_and_next_review_are_rendered_first(client: TestClient) -> None:
    created = client.post(
        "/api/v1/cases",
        json={
            "target": "https://example.net/",
            "brand": "Example Brand",
            "legit_url": "https://www.example.com/",
        },
    ).json()
    main_module = importlib.import_module("domain_abuse_toolkit.main")
    now = datetime.now(UTC)
    main_module.case_service.record_snapshot(
        SnapshotEvent(
            id="SNP-BASELINE",
            case_id=created["id"],
            status=CollectorStatus.COMPLETE,
            started_at=now,
            finished_at=now,
            occurred_at=now,
            results=[],
        ),
        [],
    )
    main_module.case_service.record_snapshot(
        SnapshotEvent(
            id="SNP-CURRENT",
            case_id=created["id"],
            status=CollectorStatus.COMPLETE,
            started_at=now,
            finished_at=now,
            occurred_at=now,
            results=[],
            previous_snapshot_id="SNP-BASELINE",
            changes=[
                SnapshotChange(
                    collector="http",
                    category="http",
                    name="hop_0.status",
                    change_type="changed",
                    before=["200"],
                    after=["404"],
                )
            ],
            next_check_due_at=now + timedelta(hours=72),
        ),
        [],
    )

    detail = client.get(f"/cases/{created['id']}")

    assert detail.status_code == 200
    assert "1 change(s) since the previous snapshot" in detail.text
    assert "200" in detail.text and "404" in detail.text
    assert "Next technical check" in detail.text
    assert "Show observations and technical artifacts" in detail.text


def test_html_forms_require_a_valid_local_csrf_token(client: TestClient) -> None:
    payload = {
        "target": "https://shop.example.net/",
        "brand": "Example Brand",
        "legit_url": "https://www.example.com/",
    }
    rejected = client.post("/cases", data=payload)
    assert rejected.status_code == 403

    payload["_csrf_token"] = _csrf_token(client)
    accepted = client.post("/cases", data=payload, follow_redirects=False)
    assert accepted.status_code == 303
    assert accepted.headers["location"].endswith("#evidence")


def test_create_case_api_has_no_external_side_effect(client: TestClient) -> None:
    response = client.post(
        "/api/v1/cases",
        json={
            "target": "https://login.example.net/account?source=test",
            "brand": "Example Brand",
            "legit_url": "https://www.example.com/",
            "suspicion_type": "phishing and credential collection",
            "urgency": "immediate",
        },
    )

    assert response.status_code == 201
    case = response.json()
    assert case["state"] == "needs_validation"
    assert case["criticality_proposed"] == "critical"
    assert case["target"]["path"] == "/account"
    assert len(case["drafts"]) == 2

    listing = client.get("/api/v1/cases")
    assert listing.status_code == 200
    assert [item["id"] for item in listing.json()] == [case["id"]]


def test_action_api_updates_case_and_rejects_cross_site_requests(
    client: TestClient,
) -> None:
    created = client.post(
        "/api/v1/cases",
        json={
            "target": "https://login.example.net/",
            "brand": "Example Brand",
            "legit_url": "https://www.example.com/",
        },
    ).json()
    action_url = f"/api/v1/cases/{created['id']}/actions/validate-evidence"

    blocked = client.patch(
        action_url,
        json={"completed": True},
        headers={"origin": "https://attacker.example", "sec-fetch-site": "cross-site"},
    )
    assert blocked.status_code == 403
    assert blocked.headers["cache-control"] == "no-store"

    updated = client.patch(action_url, json={"completed": True})
    assert updated.status_code == 200
    assert updated.json()["state"] == "needs_validation"
    assert updated.json()["actions"][0]["completed_at"] is not None

    detail = client.get(f"/cases/{created['id']}")
    assert "Case journal" in detail.text
    assert "Completed · Validate the observations and criticality" in detail.text


def test_qualification_api_requires_override_reason_and_renders_revision(
    client: TestClient,
) -> None:
    created = client.post(
        "/api/v1/cases",
        json={
            "target": "https://shop.example.net/",
            "brand": "Example Brand",
            "legit_url": "https://www.example.com/",
        },
    ).json()
    qualification_url = f"/api/v1/cases/{created['id']}/qualification"
    payload = {
        "brand_represented": True,
        "copied_elements": True,
        "sensitive_input_or_payment": False,
        "victims_or_transactions": False,
        "related_case_or_campaign": False,
        "publicly_available": True,
        "confirmed_criticality": "low",
        "reviewer": "MG",
    }

    rejected = client.post(qualification_url, json=payload)
    assert rejected.status_code == 422
    assert "reason" in rejected.json()["detail"]

    payload["override_reason"] = "No harmful transaction path observed."
    qualified = client.post(qualification_url, json=payload)
    assert qualified.status_code == 200
    assert qualified.json()["criticality_confirmed"] == "low"
    assert qualified.json()["qualification"]["reviewer"] == "MG"
    assert qualified.json()["actions"][0]["completed_at"] is not None

    detail = client.get(f"/cases/{created['id']}")
    assert "Qualify observations" in detail.text
    assert "Qualification confirmed · LOW" in detail.text
    assert "Prepare and perform reports" in detail.text
    assert "Google Safe Browsing" in detail.text
    assert "data-email-draft" in detail.text
    assert 'data-default-step="reporting"' in detail.text


def test_qualification_form_redirects_back_with_human_readable_error(
    client: TestClient,
) -> None:
    created = client.post(
        "/api/v1/cases",
        json={
            "target": "https://shop.example.net/",
            "brand": "Example Brand",
            "legit_url": "https://www.example.com/",
        },
    ).json()

    response = client.post(
        f"/cases/{created['id']}/qualification",
        data={
            "confirmed_criticality": "low",
            "reviewer": "MG",
            "_csrf_token": _csrf_token(client, f"/cases/{created['id']}"),
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert "qualification_error=" in response.headers["location"]
    assert response.headers["location"].endswith("#qualification")


def test_submission_api_requires_confirmation_and_renders_follow_up(
    client: TestClient,
) -> None:
    created = client.post(
        "/api/v1/cases",
        json={
            "target": "https://login.example.net/",
            "brand": "Example Brand",
            "legit_url": "https://www.example.com/",
            "suspicion_type": "phishing and credential collection",
        },
    ).json()
    endpoint = f"/api/v1/cases/{created['id']}/submissions"
    payload = {
        "channel_id": "google_phishing",
        "destination": "Google Safe Browsing form",
        "external_reference": "TEST-123",
        "confirmed_submitted": False,
    }

    rejected = client.post(endpoint, json=payload)
    assert rejected.status_code == 422
    assert "Confirm" in rejected.json()["detail"]

    payload["confirmed_submitted"] = True
    recorded = client.post(endpoint, json=payload)
    assert recorded.status_code == 201
    assert recorded.json()["state"] == "waiting_external"
    assert recorded.json()["submissions"][0]["external_reference"] == "TEST-123"

    detail = client.get(f"/cases/{created['id']}")
    assert detail.status_code == 200
    assert "I submitted a report" in detail.text
    assert "Report recorded" in detail.text
    assert "TEST-123" in detail.text
    assert 'data-default-step="follow-up"' in detail.text


def test_submission_form_uses_csrf_and_redirects_to_record(client: TestClient) -> None:
    created = client.post(
        "/api/v1/cases",
        json={
            "target": "https://shop.example.net/",
            "brand": "Example Brand",
            "legit_url": "https://www.example.com/",
        },
    ).json()
    case_path = f"/cases/{created['id']}"
    form_path = f"{case_path}/submissions"
    payload = {
        "channel_id": "registrar_email",
        "destination": "abuse@registrar.example",
        "external_reference": "REG-456",
        "confirmed_submitted": "true",
    }

    assert client.post(form_path, data=payload).status_code == 403
    payload["_csrf_token"] = _csrf_token(client, case_path)
    recorded = client.post(form_path, data=payload, follow_redirects=False)

    assert recorded.status_code == 303
    assert recorded.headers["location"].endswith("#follow-up")
    detail = client.get(case_path)
    assert "REG-456" in detail.text
    assert "Registrar abuse email" in detail.text


def test_reporting_page_orders_operational_channels_by_priority(
    client: TestClient,
) -> None:
    created = client.post(
        "/api/v1/cases",
        json={
            "target": "https://lovebeauteprivee.shop/",
            "brand": "Example Brand",
            "legit_url": "https://www.example.com/",
            "suspicion_type": "phishing",
        },
    ).json()

    detail = client.get(f"/cases/{created['id']}?step=reporting")

    assert detail.status_code == 200
    registrar = detail.text.index("Report to the registrar")
    protection = detail.text.index("Protect internet users")
    registry = detail.text.index("Report to the TLD registry")
    icann = detail.text.index("Escalate to ICANN Contractual Compliance")
    assert registrar < protection < registry < icann
    assert "Registrar not confirmed yet" in detail.text
    assert "GMO Registry — .shop" in detail.text
    assert "abuse@gmoregistry.com" in detail.text
    assert "ICANN Contractual Compliance" in detail.text


def test_monitoring_form_requires_authorization_and_renders_schedule(
    client: TestClient, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    main_module = importlib.import_module("domain_abuse_toolkit.main")
    monkeypatch.setattr(main_module.settings, "enable_network_collection", True)
    monkeypatch.setattr(main_module.monitoring_scheduler, "poll_once", lambda: [])
    created = client.post(
        "/api/v1/cases",
        json={
            "target": "https://monitor.example.net/",
            "brand": "Example Brand",
            "legit_url": "https://www.example.com/",
        },
    ).json()
    case_path = f"/cases/{created['id']}"
    endpoint = f"{case_path}/monitoring"
    payload = {
        "enabled": "true",
        "interval_hours": "24",
        "_csrf_token": _csrf_token(client, case_path),
    }

    rejected = client.post(endpoint, data=payload, follow_redirects=False)
    assert rejected.status_code == 303
    assert "monitoring_error=" in rejected.headers["location"]

    payload["confirmed_authorized"] = "true"
    enabled = client.post(endpoint, data=payload, follow_redirects=False)
    assert enabled.status_code == 303
    detail = client.get(case_path)
    assert "Scheduled UP/DOWN checks" in detail.text
    assert "Next automatic check" in detail.text
    assert "Every 24 hours" in detail.text


def test_evidence_archive_download_has_manifest_and_integrity_headers(
    client: TestClient,
) -> None:
    created = client.post(
        "/api/v1/cases",
        json={
            "target": "https://shop.example.net/",
            "brand": "Example Brand",
            "legit_url": "https://www.example.com/",
        },
    ).json()

    response = client.get(f"/cases/{created['id']}/evidence.zip")

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/zip"
    assert response.headers["x-evidence-artifact-count"] == "1"
    assert len(response.headers["x-evidence-archive-sha256"]) == 64
    with ZipFile(io.BytesIO(response.content)) as archive:
        assert f"{created['id']}/manifest.json" in archive.namelist()
        assert f"{created['id']}/00_case/intake.json" in archive.namelist()
