from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

_CASE_ID = re.compile(r"^[A-Z0-9][A-Z0-9-]{5,63}$")


class EvidenceStoreError(ValueError):
    """Raised when an evidence operation would violate storage policy."""


class EvidenceStore:
    """Small local store used by the pilot; originals are immutable once written."""

    def __init__(self, root: Path) -> None:
        self.root = root.expanduser().resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def _case_dir(self, case_id: str) -> Path:
        if not _CASE_ID.fullmatch(case_id):
            raise EvidenceStoreError("Invalid case identifier.")
        path = (self.root / case_id).resolve()
        if path.parent != self.root:
            raise EvidenceStoreError("Case path escapes the evidence root.")
        path.mkdir(parents=True, exist_ok=True)
        return path

    def _artifact_path(self, case_id: str, relative_path: str) -> Path:
        relative = PurePosixPath(relative_path)
        if relative.is_absolute() or not relative.parts or ".." in relative.parts:
            raise EvidenceStoreError("Invalid artifact path.")
        case_dir = self._case_dir(case_id)
        destination = case_dir.joinpath(*relative.parts).resolve()
        if case_dir not in destination.parents:
            raise EvidenceStoreError("Artifact path escapes the case directory.")
        return destination

    def write_original(
        self,
        case_id: str,
        relative_path: str,
        content: bytes,
        *,
        media_type: str,
        source: str,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        destination = self._artifact_path(case_id, relative_path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        try:
            with destination.open("xb") as stream:
                stream.write(content)
        except FileExistsError as exc:
            raise EvidenceStoreError("Original evidence is immutable and already exists.") from exc

        record = {
            "path": str(PurePosixPath(relative_path)),
            "classification": "original",
            "media_type": media_type,
            "source": source,
            "size": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
            "created_at": datetime.now(UTC).isoformat(),
            "metadata": metadata or {},
        }
        self._append_manifest(case_id, record)
        return record

    def list_case_ids(self) -> list[str]:
        """Return valid case directories without creating or modifying any files."""
        return sorted(
            entry.name
            for entry in self.root.iterdir()
            if entry.is_dir() and _CASE_ID.fullmatch(entry.name)
        )

    def read_verified_original(self, case_id: str, relative_path: str) -> bytes:
        """Read an original only when its manifest entry and SHA-256 digest are valid."""
        destination = self._artifact_path(case_id, relative_path)
        if not destination.is_file():
            raise EvidenceStoreError("The original artifact or its manifest is missing.")

        manifest = self._read_manifest(case_id)

        matching = [
            item
            for item in manifest.get("artifacts", [])
            if item.get("path") == str(PurePosixPath(relative_path))
        ]
        if len(matching) != 1 or matching[0].get("classification") != "original":
            raise EvidenceStoreError("The original artifact is not registered correctly.")

        content = destination.read_bytes()
        if hashlib.sha256(content).hexdigest() != matching[0].get("sha256"):
            raise EvidenceStoreError("The original artifact failed its integrity check.")
        return content

    def list_original_paths(self, case_id: str, prefix: str = "") -> list[str]:
        """List registered original paths, optionally below a safe POSIX prefix."""
        if prefix:
            normalized_prefix = PurePosixPath(prefix)
            if normalized_prefix.is_absolute() or ".." in normalized_prefix.parts:
                raise EvidenceStoreError("Invalid artifact prefix.")
            prefix_text = str(normalized_prefix).rstrip("/") + "/"
        else:
            prefix_text = ""

        manifest = self._read_manifest(case_id)
        paths: list[str] = []
        for item in manifest.get("artifacts", []):
            path = item.get("path")
            if not isinstance(path, str):
                raise EvidenceStoreError("The evidence manifest contains an invalid path.")
            if item.get("classification") == "original" and path.startswith(prefix_text):
                paths.append(path)
        return sorted(paths)

    def read_manifest_bytes(self, case_id: str) -> bytes:
        """Return the exact manifest bytes after validating its case identifier."""
        manifest_path = self._case_dir(case_id) / "manifest.json"
        try:
            content = manifest_path.read_bytes()
        except OSError as exc:
            raise EvidenceStoreError("The evidence manifest cannot be read.") from exc
        self._read_manifest(case_id)
        return content

    def _read_manifest(self, case_id: str) -> dict[str, Any]:
        manifest_path = self._case_dir(case_id) / "manifest.json"
        if not manifest_path.is_file():
            raise EvidenceStoreError("The evidence manifest is missing.")
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise EvidenceStoreError("The evidence manifest cannot be read.") from exc
        if not isinstance(manifest, dict) or manifest.get("case_id") != case_id:
            raise EvidenceStoreError("The evidence manifest does not match the case.")
        return manifest

    def _append_manifest(self, case_id: str, record: dict[str, Any]) -> None:
        case_dir = self._case_dir(case_id)
        manifest_path = case_dir / "manifest.json"
        if manifest_path.exists():
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        else:
            manifest = {"schema_version": "1.0", "case_id": case_id, "artifacts": []}
        if any(item["path"] == record["path"] for item in manifest["artifacts"]):
            raise EvidenceStoreError("The manifest already contains this artifact path.")
        manifest["artifacts"].append(record)
        manifest["artifacts"].sort(key=lambda item: item["path"])

        temporary = manifest_path.with_suffix(".json.tmp")
        temporary.write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        os.replace(temporary, manifest_path)

    def verify_case(self, case_id: str) -> list[str]:
        try:
            manifest = self._read_manifest(case_id)
        except EvidenceStoreError as exc:
            return [str(exc)]
        errors: list[str] = []
        records = manifest.get("artifacts")
        if not isinstance(records, list):
            return ["manifest artifact list is invalid"]
        seen: set[str] = set()
        for record in records:
            if not isinstance(record, dict) or not isinstance(record.get("path"), str):
                errors.append("manifest contains an invalid artifact record")
                continue
            relative_path = record["path"]
            if relative_path in seen:
                errors.append(f"{relative_path}: duplicate manifest path")
                continue
            seen.add(relative_path)
            try:
                path = self._artifact_path(case_id, relative_path)
            except EvidenceStoreError as exc:
                errors.append(f"{relative_path}: {exc}")
                continue
            if not path.exists():
                errors.append(f"{relative_path}: missing")
                continue
            content = path.read_bytes()
            if record.get("size") != len(content):
                errors.append(f"{relative_path}: size mismatch")
            digest = hashlib.sha256(content).hexdigest()
            if digest != record.get("sha256"):
                errors.append(f"{relative_path}: digest mismatch")
        return errors
