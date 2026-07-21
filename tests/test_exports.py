import subprocess
import sys
from zipfile import ZIP_DEFLATED, ZipFile

import pytest

from domain_abuse_toolkit.services.evidence import EvidenceStore, EvidenceStoreError
from domain_abuse_toolkit.services.exports import EvidenceExportService

CASE_ID = "DAT-20260101-ABCDEF12"


def _store_with_artifacts(tmp_path) -> EvidenceStore:  # type: ignore[no-untyped-def]
    store = EvidenceStore(tmp_path / "case-data")
    store.write_original(
        CASE_ID,
        "00_case/intake.json",
        b'{"case": "synthetic"}',
        media_type="application/json",
        source="synthetic test",
    )
    store.write_original(
        CASE_ID,
        "01_http/response.bin",
        b"synthetic evidence bytes",
        media_type="application/octet-stream",
        source="synthetic test",
    )
    return store


def test_export_is_deterministic_and_contains_only_registered_material(tmp_path) -> None:  # type: ignore[no-untyped-def]
    store = _store_with_artifacts(tmp_path)
    service = EvidenceExportService(store, max_uncompressed_bytes=1024 * 1024)

    first = service.build(CASE_ID)
    second = service.build(CASE_ID)

    assert first.content == second.content
    assert first.sha256 == second.sha256
    assert first.artifact_count == 2
    archive_path = tmp_path / "evidence.zip"
    archive_path.write_bytes(first.content)
    with ZipFile(archive_path) as archive:
        assert set(archive.namelist()) == {
            f"{CASE_ID}/manifest.json",
            f"{CASE_ID}/00_case/intake.json",
            f"{CASE_ID}/01_http/response.bin",
            f"{CASE_ID}/verify_evidence.py",
            f"{CASE_ID}/VERIFY_README.txt",
        }


def test_offline_verifier_accepts_export_and_rejects_extra_member(tmp_path) -> None:  # type: ignore[no-untyped-def]
    service = EvidenceExportService(
        _store_with_artifacts(tmp_path), max_uncompressed_bytes=1024 * 1024
    )
    exported = service.build(CASE_ID)
    archive_path = tmp_path / "evidence.zip"
    archive_path.write_bytes(exported.content)

    with ZipFile(archive_path) as archive:
        verifier_path = tmp_path / "verify_evidence.py"
        verifier_path.write_bytes(archive.read(f"{CASE_ID}/verify_evidence.py"))
    verified = subprocess.run(
        [sys.executable, str(verifier_path), str(archive_path)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert verified.returncode == 0
    assert f"VERIFIED: {CASE_ID} (2 artifacts)" in verified.stdout

    extracted = tmp_path / "extracted"
    with ZipFile(archive_path) as archive:
        archive.extractall(extracted)
    verified_directory = subprocess.run(
        [sys.executable, str(verifier_path), str(extracted)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert verified_directory.returncode == 0
    (extracted / CASE_ID / "unexpected.txt").write_text("not registered", encoding="utf-8")
    rejected_directory = subprocess.run(
        [sys.executable, str(verifier_path), str(extracted)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert rejected_directory.returncode == 1
    assert "unexpected package file" in rejected_directory.stderr

    with ZipFile(archive_path, mode="a", compression=ZIP_DEFLATED) as archive:
        archive.writestr(f"{CASE_ID}/unexpected.txt", b"not registered")
    rejected = subprocess.run(
        [sys.executable, str(verifier_path), str(archive_path)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert rejected.returncode == 1
    assert "unexpected archive member" in rejected.stderr


def test_export_refuses_tampering_and_size_limit(tmp_path) -> None:  # type: ignore[no-untyped-def]
    store = _store_with_artifacts(tmp_path)
    artifact = tmp_path / "case-data" / CASE_ID / "01_http" / "response.bin"
    artifact.write_bytes(b"tampered")
    service = EvidenceExportService(store, max_uncompressed_bytes=1024 * 1024)
    with pytest.raises(EvidenceStoreError, match="integrity"):
        service.build(CASE_ID)

    clean_store = _store_with_artifacts(tmp_path / "second")
    limited = EvidenceExportService(clean_store, max_uncompressed_bytes=32)
    with pytest.raises(EvidenceStoreError, match="size limit"):
        limited.build(CASE_ID)
