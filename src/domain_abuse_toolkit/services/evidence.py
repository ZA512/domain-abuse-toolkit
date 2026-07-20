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
        manifest_path = self._case_dir(case_id) / "manifest.json"
        if not destination.is_file() or not manifest_path.is_file():
            raise EvidenceStoreError("The original artifact or its manifest is missing.")

        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise EvidenceStoreError("The evidence manifest cannot be read.") from exc

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
        case_dir = self._case_dir(case_id)
        manifest_path = case_dir / "manifest.json"
        if not manifest_path.exists():
            return ["manifest.json is missing"]
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        errors: list[str] = []
        for record in manifest.get("artifacts", []):
            path = self._artifact_path(case_id, record["path"])
            if not path.exists():
                errors.append(f"{record['path']}: missing")
                continue
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            if digest != record["sha256"]:
                errors.append(f"{record['path']}: digest mismatch")
        return errors
