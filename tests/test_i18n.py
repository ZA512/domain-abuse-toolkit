import importlib

from fastapi.testclient import TestClient

from domain_abuse_toolkit.config import get_settings
from domain_abuse_toolkit.services.i18n import Translator


def test_english_is_reference_and_french_catalogue_is_complete() -> None:
    english = Translator("en")
    french = Translator("fr")

    assert english("home.create") == "Create a case"
    assert french("home.create") == "Créer un dossier"
    assert french.selected_keys == english.reference_keys
    assert Translator.available_locales() == ("en", "fr")


def test_selected_catalogue_falls_back_to_english_for_a_missing_key() -> None:
    french = Translator("fr")
    french._selected.pop("home.create")

    assert french("home.create") == "Create a case"


def test_french_can_be_selected_at_startup(tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("DAT_UI_LANGUAGE", "fr")
    monkeypatch.setenv("DAT_DATA_DIR", str(tmp_path / "case-data"))
    get_settings.cache_clear()
    main_module = importlib.import_module("domain_abuse_toolkit.main")
    main_module = importlib.reload(main_module)

    response = TestClient(main_module.app).get("/")

    assert response.status_code == 200
    assert '<html lang="fr">' in response.text
    assert "Transformez une URL suspecte en dossier exploitable" in response.text
