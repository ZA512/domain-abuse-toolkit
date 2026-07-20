from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape

from domain_abuse_toolkit.models import CaseCreate, Draft, NormalizedTarget


class DraftService:
    TEMPLATE_VERSION = "registrar-v1"

    def __init__(self) -> None:
        template_dir = Path(__file__).resolve().parent.parent / "resources" / "message_templates"
        self.environment = Environment(
            loader=FileSystemLoader(template_dir),
            undefined=StrictUndefined,
            autoescape=select_autoescape(default_for_string=False),
            keep_trailing_newline=True,
        )

    def registrar_drafts(self, intake: CaseCreate, target: NormalizedTarget) -> list[Draft]:
        context = {
            "domain": target.registrable_domain,
            "url": target.normalized_url,
            "brand": intake.brand,
            "legit_url": intake.legit_url,
            "suspicion_type": intake.suspicion_type,
        }
        drafts = []
        for language in ("en", "fr"):
            subject_template = self.environment.get_template(f"registrar_subject_{language}.txt")
            body_template = self.environment.get_template(f"registrar_body_{language}.txt")
            drafts.append(
                Draft(
                    language=language,
                    destination_role="registrar abuse team",
                    subject=subject_template.render(**context).strip(),
                    body=body_template.render(**context).strip(),
                    template_version=self.TEMPLATE_VERSION,
                    missing_placeholders=["sender_name", "sender_role", "company"],
                )
            )
        return drafts

