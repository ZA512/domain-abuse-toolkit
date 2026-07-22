from __future__ import annotations

import json
import re
from importlib.resources import files
from typing import Any


class TranslationCatalogueError(ValueError):
    pass


class Translator:
    """Load a selected UI catalogue with English as the reference fallback."""

    def __init__(self, locale: str = "en") -> None:
        self.locale = locale
        self._reference = self._load("en")
        self._selected = self._reference if locale == "en" else self._load(locale)

    @staticmethod
    def _load(locale: str) -> dict[str, str]:
        resource = files("domain_abuse_toolkit.resources").joinpath(
            "i18n", f"{locale}.json"
        )
        try:
            payload = json.loads(resource.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise TranslationCatalogueError(
                f"UI translation catalogue '{locale}' is missing or invalid."
            ) from exc
        if not isinstance(payload, dict) or not all(
            isinstance(key, str) and isinstance(value, str)
            for key, value in payload.items()
        ):
            raise TranslationCatalogueError(
                f"UI translation catalogue '{locale}' must contain string pairs."
            )
        return payload

    def __call__(self, key: str, default: str | None = None, **values: Any) -> str:
        text = self._selected.get(key, self._reference.get(key, default or key))
        try:
            return text.format(**values)
        except (KeyError, ValueError) as exc:
            raise TranslationCatalogueError(
                f"Invalid placeholders for translation key '{key}'."
            ) from exc

    @property
    def reference_keys(self) -> frozenset[str]:
        return frozenset(self._reference)

    @property
    def selected_keys(self) -> frozenset[str]:
        return frozenset(self._selected)

    @staticmethod
    def available_locales() -> tuple[str, ...]:
        directory = files("domain_abuse_toolkit.resources").joinpath("i18n")
        locales = {
            item.name.removesuffix(".json")
            for item in directory.iterdir()
            if item.is_file()
            and item.name.endswith(".json")
            and re.fullmatch(r"[a-z]{2}(?:-[A-Z]{2})?\.json", item.name)
        }
        return tuple(sorted(locales, key=lambda locale: (locale != "en", locale)))
