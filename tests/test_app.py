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
    assert "Turn a suspicious URL into an actionable case" in home.text
    assert home.headers["x-frame-options"] == "DENY"


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
    assert "Opening this case never contacts the target" in detail.text
    assert "Network collection is disabled by default" in detail.text


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
    assert "1 change since SNP-BASELINE" in detail.text
    assert "200" in detail.text and "404" in detail.text
    assert "Next technical review" in detail.text
    assert "Show collector details and unchanged observations" in detail.text


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
    assert updated.json()["state"] == "collecting"
    assert updated.json()["actions"][0]["completed_at"] is not None

    detail = client.get(f"/cases/{created['id']}")
    assert "Workflow history" in detail.text
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
    assert "Human validation desk" in detail.text
    assert "Qualification confirmed · LOW" in detail.text
    assert "Open the right official channel" in detail.text
    assert "Google Safe Browsing" in detail.text
    assert "data-email-draft" in detail.text


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
    assert "Record a completed submission" in detail.text
    assert "External submission recorded" in detail.text
    assert "TEST-123" in detail.text


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
    assert recorded.headers["location"].endswith("#record-submission")
    detail = client.get(case_path)
    assert "REG-456" in detail.text
    assert "Registrar abuse email" in detail.text


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
