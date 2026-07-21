import json

import pytest

from domain_abuse_toolkit.services.evidence import EvidenceStore, EvidenceStoreError


def test_original_artifact_is_hashed_and_verified(tmp_path) -> None:  # type: ignore[no-untyped-def]
    store = EvidenceStore(tmp_path)
    record = store.write_original(
        "DAT-20260101-ABCDEF12",
        "01_http/response.bin",
        b"original bytes",
        media_type="application/octet-stream",
        source="synthetic test",
    )

    assert record["sha256"] == "52c3935626c104b2cbc9031291a1c4d56614c38f52072a361d658a58a9c48698"
    assert store.verify_case("DAT-20260101-ABCDEF12") == []

    manifest = json.loads(
        (tmp_path / "DAT-20260101-ABCDEF12" / "manifest.json").read_text(encoding="utf-8")
    )
    assert manifest["artifacts"][0]["classification"] == "original"


def test_original_cannot_be_overwritten(tmp_path) -> None:  # type: ignore[no-untyped-def]
    store = EvidenceStore(tmp_path)
    arguments = {
        "case_id": "DAT-20260101-ABCDEF12",
        "relative_path": "file.txt",
        "content": b"first",
        "media_type": "text/plain",
        "source": "synthetic test",
    }
    store.write_original(**arguments)
    with pytest.raises(EvidenceStoreError):
        store.write_original(**arguments)


def test_verified_original_can_be_read_and_tampering_is_rejected(tmp_path) -> None:  # type: ignore[no-untyped-def]
    store = EvidenceStore(tmp_path)
    store.write_original(
        "DAT-20260101-ABCDEF12",
        "00_case/intake.json",
        b'{"safe": true}',
        media_type="application/json",
        source="synthetic test",
    )
    assert store.read_verified_original(
        "DAT-20260101-ABCDEF12", "00_case/intake.json"
    ) == b'{"safe": true}'

    (tmp_path / "DAT-20260101-ABCDEF12" / "00_case" / "intake.json").write_bytes(
        b'{"safe": false}'
    )
    with pytest.raises(EvidenceStoreError, match="integrity"):
        store.read_verified_original("DAT-20260101-ABCDEF12", "00_case/intake.json")


def test_original_paths_can_be_filtered_by_safe_prefix(tmp_path) -> None:  # type: ignore[no-untyped-def]
    store = EvidenceStore(tmp_path)
    for path in ("00_case/intake.json", "00_case/events/event.json"):
        store.write_original(
            "DAT-20260101-ABCDEF12",
            path,
            path.encode(),
            media_type="application/json",
            source="synthetic test",
        )

    assert store.list_original_paths(
        "DAT-20260101-ABCDEF12", "00_case/events"
    ) == ["00_case/events/event.json"]
    with pytest.raises(EvidenceStoreError, match="prefix"):
        store.list_original_paths("DAT-20260101-ABCDEF12", "../outside")


def test_case_verification_reports_a_broken_manifest_without_crashing(tmp_path) -> None:  # type: ignore[no-untyped-def]
    store = EvidenceStore(tmp_path)
    store.write_original(
        "DAT-20260101-ABCDEF12",
        "00_case/intake.json",
        b"{}",
        media_type="application/json",
        source="synthetic test",
    )
    (tmp_path / "DAT-20260101-ABCDEF12" / "manifest.json").write_text(
        "not json", encoding="utf-8"
    )

    errors = store.verify_case("DAT-20260101-ABCDEF12")

    assert errors == ["The evidence manifest cannot be read."]


@pytest.mark.parametrize("relative", ["../secret", "/absolute", "folder/../../secret"])
def test_artifact_path_cannot_escape_case(tmp_path, relative: str) -> None:  # type: ignore[no-untyped-def]
    store = EvidenceStore(tmp_path)
    with pytest.raises(EvidenceStoreError):
        store.write_original(
            "DAT-20260101-ABCDEF12",
            relative,
            b"test",
            media_type="text/plain",
            source="synthetic test",
        )
