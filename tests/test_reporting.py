import pytest

from domain_abuse_toolkit.models import CaseCreate, QualificationSubmission
from domain_abuse_toolkit.services.cases import CaseService
from domain_abuse_toolkit.services.drafts import DraftService
from domain_abuse_toolkit.services.evidence import EvidenceStore
from domain_abuse_toolkit.services.reporting import ReportingCatalogueError, ReportingService


def _qualified_case(tmp_path):  # type: ignore[no-untyped-def]
    case_service = CaseService(EvidenceStore(tmp_path), DraftService())
    case = case_service.create(
        CaseCreate(
            target="https://login.example.net/account",
            brand="Example Brand",
            legit_url="https://www.example.com/",
            suspicion_type="phishing and credential collection",
        )
    )
    case_service.submit_qualification(
        case.id,
        QualificationSubmission(
            brand_represented=True,
            copied_elements=True,
            sensitive_input_or_payment=True,
            victims_or_transactions=False,
            related_case_or_campaign=False,
            publicly_available=True,
            confirmed_criticality=case.criticality_proposed,
            reviewer="MG",
        ),
    )
    return case


def test_catalogue_contains_only_unique_active_https_channels() -> None:
    service = ReportingService()

    assert {channel.id for channel in service.channels} == {
        "google_malware",
        "google_phishing",
        "icann_lookup",
        "icann_compliance",
        "microsoft_unsafe_site",
        "pharos_fr",
        "registry_gmo_shop",
    }
    assert all(channel.status == "active" for channel in service.channels)
    assert all(str(channel.action_url).startswith("https://") for channel in service.channels)


def test_phishing_case_prioritizes_relevant_official_channels(tmp_path) -> None:  # type: ignore[no-untyped-def]
    case = _qualified_case(tmp_path)
    views = ReportingService().channel_views(case)
    by_id = {item["channel"].id: item for item in views}  # type: ignore[union-attr]

    assert by_id["icann_lookup"]["recommended"] is True
    assert by_id["google_phishing"]["recommended"] is True
    assert by_id["microsoft_unsafe_site"]["recommended"] is True
    assert by_id["google_malware"]["recommended"] is False


def test_bilingual_form_summaries_use_only_confirmed_observations(tmp_path) -> None:  # type: ignore[no-untyped-def]
    summaries = ReportingService().summaries(_qualified_case(tmp_path))

    assert "Reported URL: https://login.example.net/account" in summaries["en"]
    assert "Credential, personal-data or payment path observed" in summaries["en"]
    assert "Victims or fraudulent transactions known" not in summaries["en"]
    assert "URL signalée : https://login.example.net/account" in summaries["fr"]
    assert "Accessible publiquement au moment de la revue" in summaries["fr"]


def test_stale_channel_is_never_suggested(tmp_path) -> None:  # type: ignore[no-untyped-def]
    service = ReportingService()
    service.channels = [
        channel.model_copy(update={"status": "review_needed"})
        if channel.id == "icann_lookup"
        else channel
        for channel in service.channels
    ]

    views = service.channel_views(_qualified_case(tmp_path))
    icann = next(item for item in views if item["channel"].id == "icann_lookup")  # type: ignore[union-attr]

    assert icann["recommended"] is False
    assert "reverified" in str(icann["recommendation_reason"])


def test_only_real_reporting_channels_can_be_recorded() -> None:
    service = ReportingService()

    registrar = service.resolve_submission_channel("registrar_email")
    assert registrar["category"] == "registrar_report"
    assert all(option["category"] != "contact_discovery" for option in service.submission_options())
    with pytest.raises(ReportingCatalogueError, match="Unknown or unavailable"):
        service.resolve_submission_channel("icann_lookup")


def test_shop_registry_is_scoped_and_icann_is_last(tmp_path) -> None:  # type: ignore[no-untyped-def]
    case_service = CaseService(EvidenceStore(tmp_path), DraftService())
    shop_case = case_service.create(
        CaseCreate(
            target="https://lovebeauteprivee.shop/",
            brand="Example Brand",
            legit_url="https://www.example.com/",
        )
    )
    net_case = _qualified_case(tmp_path)
    service = ReportingService()

    shop_groups = service.grouped_channel_views(shop_case)
    assert [item["channel"].id for item in shop_groups["registry"]] == [  # type: ignore[union-attr]
        "registry_gmo_shop"
    ]
    assert shop_groups["icann"][0]["channel"].id == "icann_compliance"  # type: ignore[union-attr]
    assert all(
        option["id"] != "registry_gmo_shop"
        for option in service.submission_options(net_case)
    )
    assert any(
        option["id"] == "registry_gmo_shop"
        for option in service.submission_options(shop_case)
    )


def test_registry_draft_targets_the_official_tld_operator(tmp_path) -> None:  # type: ignore[no-untyped-def]
    case_service = CaseService(EvidenceStore(tmp_path), DraftService())
    case = case_service.create(
        CaseCreate(
            target="https://lovebeauteprivee.shop/",
            brand="Example Brand",
            legit_url="https://www.example.com/",
        )
    )

    drafts = DraftService().registry_drafts(
        case, registry_name="GMO Registry — .shop", tld=".shop"
    )

    assert len(drafts) == 2
    assert "lovebeauteprivee.shop" in drafts[0].subject
    assert "GMO Registry" in drafts[0].body
    assert "Référence interne" in drafts[1].body
