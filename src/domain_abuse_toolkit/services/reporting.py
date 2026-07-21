from __future__ import annotations

import json
from importlib.resources import files

from pydantic import TypeAdapter, ValidationError

from domain_abuse_toolkit.models import CaseRecord, ReportingChannel


class ReportingCatalogueError(ValueError):
    pass


class ReportingService:
    """Versioned official-channel catalogue and deterministic form summaries."""

    def __init__(self) -> None:
        resource = files("domain_abuse_toolkit.resources").joinpath(
            "reporting_channels.json"
        )
        try:
            payload = json.loads(resource.read_text(encoding="utf-8"))
            channels = TypeAdapter(list[ReportingChannel]).validate_python(
                payload["channels"]
            )
        except (OSError, json.JSONDecodeError, KeyError, ValidationError) as exc:
            raise ReportingCatalogueError("The reporting catalogue is invalid.") from exc
        identifiers = [channel.id for channel in channels]
        if len(identifiers) != len(set(identifiers)):
            raise ReportingCatalogueError("The reporting catalogue has duplicate identifiers.")
        self.channels = channels

    def resolve_submission_channel(self, channel_id: str) -> dict[str, str]:
        if channel_id == "registrar_email":
            return {
                "id": "registrar_email",
                "name": "Registrar abuse email",
                "category": "registrar_report",
            }
        channel = next(
            (
                item
                for item in self.channels
                if item.id == channel_id
                and item.status == "active"
                and item.category != "contact_discovery"
            ),
            None,
        )
        if channel is None:
            raise ReportingCatalogueError("Unknown or unavailable reporting channel.")
        return {"id": channel.id, "name": channel.name, "category": channel.category}

    def submission_options(self) -> list[dict[str, str]]:
        options = [
            {
                "id": "registrar_email",
                "name": "Registrar abuse email",
                "category": "registrar_report",
            },
        ]
        options.extend(
            {"id": channel.id, "name": channel.name, "category": channel.category}
            for channel in self.channels
            if channel.status == "active" and channel.category != "contact_discovery"
        )
        return options

    @staticmethod
    def _recommendation(channel: ReportingChannel, case: CaseRecord) -> tuple[bool, str]:
        suspicion = case.suspicion_type.casefold()
        qualification = case.qualification
        if channel.id == "icann_lookup":
            return True, "Use this first to identify the registrar abuse contact."
        if channel.id == "google_phishing":
            relevant = any(marker in suspicion for marker in ("phishing", "credential"))
            if qualification and qualification.sensitive_input_or_payment:
                relevant = True
            return relevant, "Recommended when phishing or credential collection is observed."
        if channel.id == "google_malware":
            return "malware" in suspicion, "Recommended only for observed malware behavior."
        if channel.id == "microsoft_unsafe_site":
            return True, "General user-protection review for unsafe URLs."
        if channel.id == "pharos_fr":
            relevant = bool(
                qualification
                and (qualification.victims_or_transactions or qualification.publicly_available)
            )
            return relevant, "Human decision required: use only when the official scope applies."
        return False, "Available as an optional official channel."

    def channel_views(self, case: CaseRecord) -> list[dict[str, object]]:
        views = []
        for channel in self.channels:
            if channel.status == "deprecated":
                continue
            if channel.status == "review_needed":
                recommended = False
                reason = "This official channel must be reverified before use."
            else:
                recommended, reason = self._recommendation(channel, case)
            views.append(
                {
                    "channel": channel,
                    "recommended": recommended,
                    "recommendation_reason": reason,
                    "action_url": str(channel.action_url),
                    "source_url": str(channel.source_url),
                }
            )
        return sorted(
            views,
            key=lambda item: (
                not bool(item["recommended"]),
                str(item["channel"].name),  # type: ignore[union-attr]
            ),
        )

    @staticmethod
    def summaries(case: CaseRecord) -> dict[str, str]:
        criticality = case.criticality_confirmed or case.criticality_proposed
        observations_en: list[str] = []
        observations_fr: list[str] = []
        qualification = case.qualification
        if qualification:
            facts = [
                (
                    qualification.brand_represented,
                    "Brand identity represented",
                    "Identité de marque représentée",
                ),
                (
                    qualification.copied_elements,
                    "Copied content or visuals observed",
                    "Contenus ou visuels copiés observés",
                ),
                (
                    qualification.sensitive_input_or_payment,
                    "Credential, personal-data or payment path observed",
                    "Saisie d'identifiants, de données personnelles ou paiement observée",
                ),
                (
                    qualification.victims_or_transactions,
                    "Victims or fraudulent transactions known",
                    "Victimes ou transactions frauduleuses connues",
                ),
                (
                    qualification.related_case_or_campaign,
                    "Related case or campaign known",
                    "Dossier ou campagne lié connu",
                ),
                (
                    qualification.publicly_available,
                    "Publicly available at review time",
                    "Accessible publiquement au moment de la revue",
                ),
            ]
            for present, english, french in facts:
                if present:
                    observations_en.append(f"- {english}")
                    observations_fr.append(f"- {french}")
        if not observations_en:
            observations_en.append("- Human qualification not yet recorded")
            observations_fr.append("- Qualification humaine non encore enregistrée")

        english = "\n".join(
            [
                f"Internal reference: {case.id}",
                f"Reported URL: {case.target.normalized_url}",
                f"Affected brand: {case.brand}",
                f"Suspected abuse: {case.suspicion_type}",
                f"Criticality: {criticality.value}",
                "Human-verified observations:",
                *observations_en,
                "Evidence package with SHA-256 manifest is available on request.",
            ]
        )
        french = "\n".join(
            [
                f"Référence interne : {case.id}",
                f"URL signalée : {case.target.normalized_url}",
                f"Marque concernée : {case.brand}",
                f"Abus suspecté : {case.suspicion_type}",
                f"Criticité : {criticality.value}",
                "Constats validés humainement :",
                *observations_fr,
                "Un dossier de preuve avec manifeste SHA-256 est disponible sur demande.",
            ]
        )
        return {"en": english, "fr": french}
