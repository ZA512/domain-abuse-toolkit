from __future__ import annotations

import hashlib
import io
import json
from dataclasses import dataclass
from importlib.resources import files
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

from domain_abuse_toolkit.services.evidence import EvidenceStore, EvidenceStoreError


@dataclass(frozen=True)
class EvidenceArchive:
    content: bytes
    sha256: str
    manifest_sha256: str
    artifact_count: int


class EvidenceExportService:
    """Build deterministic, self-verifying case archives from registered artifacts only."""

    def __init__(self, evidence_store: EvidenceStore, *, max_uncompressed_bytes: int) -> None:
        self.evidence_store = evidence_store
        self.max_uncompressed_bytes = max_uncompressed_bytes

    @staticmethod
    def _write_member(archive: ZipFile, name: str, content: bytes) -> None:
        info = ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
        info.compress_type = ZIP_DEFLATED
        info.external_attr = 0o100644 << 16
        archive.writestr(info, content, compresslevel=6)

    def build(self, case_id: str) -> EvidenceArchive:
        manifest_bytes = self.evidence_store.read_manifest_bytes(case_id)
        try:
            manifest = json.loads(manifest_bytes)
        except json.JSONDecodeError as exc:
            raise EvidenceStoreError("The evidence manifest cannot be exported.") from exc

        records = manifest.get("artifacts")
        if not isinstance(records, list):
            raise EvidenceStoreError("The evidence manifest has no valid artifact list.")

        artifacts: list[tuple[str, bytes]] = []
        seen_paths: set[str] = set()
        total_size = len(manifest_bytes)
        for record in records:
            if not isinstance(record, dict) or not isinstance(record.get("path"), str):
                raise EvidenceStoreError("The evidence manifest contains an invalid record.")
            path = record["path"]
            if path in seen_paths:
                raise EvidenceStoreError("The evidence manifest contains a duplicate path.")
            seen_paths.add(path)
            content = self.evidence_store.read_verified_artifact(case_id, path)
            if record.get("size") != len(content):
                raise EvidenceStoreError(f"{path}: size mismatch")
            total_size += len(content)
            if total_size > self.max_uncompressed_bytes:
                raise EvidenceStoreError("The evidence package exceeds the export size limit.")
            artifacts.append((path, content))

        resource_root = files("domain_abuse_toolkit.resources.export")
        verifier = resource_root.joinpath("verify_evidence.py").read_bytes()
        instructions = resource_root.joinpath("VERIFY_README.txt").read_bytes()

        stream = io.BytesIO()
        prefix = f"{case_id}/"
        with ZipFile(stream, mode="w", compression=ZIP_DEFLATED, compresslevel=6) as archive:
            self._write_member(archive, f"{prefix}manifest.json", manifest_bytes)
            for path, content in sorted(artifacts):
                self._write_member(archive, f"{prefix}{path}", content)
            self._write_member(archive, f"{prefix}verify_evidence.py", verifier)
            self._write_member(archive, f"{prefix}VERIFY_README.txt", instructions)

        content = stream.getvalue()
        return EvidenceArchive(
            content=content,
            sha256=hashlib.sha256(content).hexdigest(),
            manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
            artifact_count=len(artifacts),
        )
