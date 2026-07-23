from __future__ import annotations

import json
from importlib.resources import files
from urllib.parse import quote

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

    @staticmethod
    def tld(case: CaseRecord) -> str:
        return case.target.registrable_domain.rsplit(".", 1)[-1].casefold()

    def _applies(self, channel: ReportingChannel, case: CaseRecord | None) -> bool:
        return not channel.applicable_tlds or (
            case is not None and self.tld(case) in channel.applicable_tlds
        )

    def resolve_submission_channel(
        self, channel_id: str, case: CaseRecord | None = None
    ) -> dict[str, str]:
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
                and self._applies(item, case)
            ),
            None,
        )
        if channel is None:
            raise ReportingCatalogueError("Unknown or unavailable reporting channel.")
        return {"id": channel.id, "name": channel.name, "category": channel.category}

    def submission_options(self, case: CaseRecord | None = None) -> list[dict[str, str]]:
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
            if channel.status == "active"
            and channel.category != "contact_discovery"
            and self._applies(channel, case)
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
        if channel.priority_group == "registry":
            return (
                True,
                "Contact the TLD registry after the registrar and user-protection channels.",
            )
        if channel.priority_group == "icann":
            return False, "Escalate only after a direct registrar or registry report."
        return False, "Available as an optional official channel."

    def channel_views(self, case: CaseRecord, translate=None) -> list[dict[str, object]]:
        views = []
        for channel in self.channels:
            if channel.status == "deprecated":
                continue
            if not self._applies(channel, case):
                continue
            if channel.status == "review_needed":
                recommended = False
                reason = "This official channel must be reverified before use."
            else:
                recommended, reason = self._recommendation(channel, case)
            purpose = channel.purpose
            notes = channel.notes
            required_fields = channel.required_fields
            category_label = channel.category.replace("_", " ")
            if translate:
                purpose = translate(
                    f"channel.{channel.id}.purpose", default=channel.purpose
                )
                notes = translate(f"channel.{channel.id}.notes", default=channel.notes)
                required_fields = [
                    translate(f"channel.field.{field}", default=field)
                    for field in channel.required_fields
                ]
                category_label = translate(
                    f"channel.category.{channel.category}", default=category_label
                )
                reason = translate(
                    f"channel.{channel.id}.recommendation", default=reason
                )
            action_url = str(channel.action_url)
            if channel.id == "icann_lookup":
                action_url = (
                    "https://lookup.icann.org/en/lookup?name="
                    f"{quote(case.target.registrable_domain, safe='')}"
                )
            views.append(
                {
                    "channel": channel,
                    "recommended": recommended,
                    "recommendation_reason": reason,
                    "purpose": purpose,
                    "notes": notes,
                    "required_fields": required_fields,
                    "category_label": category_label,
                    "action_url": action_url,
                    "source_url": str(channel.source_url),
                }
            )
        group_rank = {
            "discovery": 0,
            "user_protection": 1,
            "registry": 2,
            "icann": 3,
            "other": 4,
        }
        return sorted(
            views,
            key=lambda item: (
                group_rank[str(item["channel"].priority_group)],  # type: ignore[union-attr]
                not bool(item["recommended"]),
                str(item["channel"].name),  # type: ignore[union-attr]
            ),
        )

    def grouped_channel_views(
        self, case: CaseRecord, translate=None
    ) -> dict[str, list[dict[str, object]]]:
        groups = {
            "discovery": [],
            "user_protection": [],
            "registry": [],
            "icann": [],
            "other": [],
        }
        for view in self.channel_views(case, translate):
            group = str(view["channel"].priority_group)  # type: ignore[union-attr]
            groups[group].append(view)
        return groups

    @staticmethod
    def registrar_actor(case: CaseRecord) -> dict[str, str | bool | None]:
        values: dict[str, str] = {}
        wanted = {
            "registrar.name": "name",
            "registrar.handle": "handle",
            "registrar.abuse_email": "email",
        }
        for snapshot in reversed(case.snapshots):
            rdap = next(
                (result for result in snapshot.results if result.collector == "rdap"),
                None,
            )
            if rdap is None:
                continue
            for observation in rdap.observations:
                key = wanted.get(observation.name)
                if key and key not in values:
                    values[key] = observation.value
            if values:
                break
        return {
            "known": bool(values.get("name") or values.get("email")),
            "name": values.get("name"),
            "handle": values.get("handle"),
            "email": values.get("email"),
        }

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
