import importlib

import pytest
from fastapi.testclient import TestClient

from domain_abuse_toolkit.config import get_settings


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
