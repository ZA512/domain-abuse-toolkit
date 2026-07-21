#!/usr/bin/env python3
"""Verify a Domain Abuse Toolkit evidence ZIP or extracted directory."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path, PurePosixPath
from zipfile import BadZipFile, ZipFile

MAX_MANIFEST_BYTES = 5 * 1024 * 1024
MAX_ARTIFACT_BYTES = 256 * 1024 * 1024
MAX_TOTAL_BYTES = 1024 * 1024 * 1024
MAX_MEMBERS = 10_000
HELPER_NAMES = {"manifest.json", "verify_evidence.py", "VERIFY_README.txt"}


class VerificationError(ValueError):
    pass


def safe_relative_path(value: str) -> PurePosixPath:
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or ".." in path.parts:
        raise VerificationError(f"unsafe path: {value!r}")
    return path


def parse_manifest(content: bytes) -> dict[str, object]:
    if len(content) > MAX_MANIFEST_BYTES:
        raise VerificationError("manifest exceeds the size limit")
    try:
        manifest = json.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VerificationError("manifest is not valid UTF-8 JSON") from exc
    if not isinstance(manifest, dict) or not isinstance(manifest.get("case_id"), str):
        raise VerificationError("manifest has no valid case identifier")
    if not isinstance(manifest.get("artifacts"), list):
        raise VerificationError("manifest has no valid artifact list")
    return manifest


def verify_records(manifest: dict[str, object], read_artifact) -> int:  # type: ignore[no-untyped-def]
    seen: set[str] = set()
    derivations: list[tuple[str, list[str]]] = []
    total = 0
    records = manifest["artifacts"]
    assert isinstance(records, list)
    for record in records:
        if not isinstance(record, dict):
            raise VerificationError("manifest contains an invalid artifact record")
        path_value = record.get("path")
        digest = record.get("sha256")
        expected_size = record.get("size")
        if not isinstance(path_value, str) or not isinstance(digest, str):
            raise VerificationError("artifact path or digest is invalid")
        if not isinstance(expected_size, int) or expected_size < 0:
            raise VerificationError(f"{path_value}: invalid size")
        path = str(safe_relative_path(path_value))
        classification = record.get("classification")
        if classification not in {"original", "derived"}:
            raise VerificationError(f"{path}: invalid classification")
        if classification == "derived":
            sources = record.get("derived_from")
            if (
                not isinstance(sources, list)
                or not sources
                or any(not isinstance(source, str) for source in sources)
            ):
                raise VerificationError(f"{path}: invalid derivation sources")
            derivations.append((path, sources))
        if path in seen:
            raise VerificationError(f"duplicate artifact path: {path}")
        seen.add(path)
        if expected_size > MAX_ARTIFACT_BYTES:
            raise VerificationError(f"{path}: artifact exceeds the size limit")
        total += expected_size
        if total > MAX_TOTAL_BYTES:
            raise VerificationError("package exceeds the total size limit")
        content = read_artifact(path, expected_size)
        if len(content) != expected_size:
            raise VerificationError(f"{path}: size mismatch")
        if hashlib.sha256(content).hexdigest() != digest:
            raise VerificationError(f"{path}: SHA-256 mismatch")
    for path, sources in derivations:
        for source in sources:
            normalized_source = str(safe_relative_path(source))
            if normalized_source not in seen or normalized_source == path:
                raise VerificationError(f"{path}: unknown derivation source")
    return len(seen)


def verify_directory(root: Path) -> tuple[str, int]:
    root = root.resolve()
    manifest_path = root / "manifest.json"
    if not manifest_path.is_file():
        candidates = list(root.glob("*/manifest.json"))
        if len(candidates) != 1:
            raise VerificationError("expected exactly one manifest.json")
        root = candidates[0].parent.resolve()
        manifest_path = candidates[0]
    if manifest_path.is_symlink():
        raise VerificationError("manifest must not be a symbolic link")
    manifest = parse_manifest(manifest_path.read_bytes())

    def read_artifact(path: str, expected_size: int) -> bytes:
        target = root.joinpath(*PurePosixPath(path).parts)
        if target.is_symlink() or not target.is_file():
            raise VerificationError(f"{path}: missing or symbolic link")
        resolved = target.resolve()
        if root not in resolved.parents:
            raise VerificationError(f"{path}: escapes the package directory")
        if target.stat().st_size != expected_size:
            raise VerificationError(f"{path}: size mismatch")
        return target.read_bytes()

    count = verify_records(manifest, read_artifact)
    allowed = set(HELPER_NAMES)
    allowed.update(str(record["path"]) for record in manifest["artifacts"])
    for candidate in root.rglob("*"):
        if candidate.is_symlink():
            raise VerificationError("package contains a symbolic link")
        if candidate.is_file():
            relative = candidate.relative_to(root).as_posix()
            if relative not in allowed:
                raise VerificationError(f"unexpected package file: {relative}")
    return str(manifest["case_id"]), count


def verify_zip(path: Path) -> tuple[str, int]:
    try:
        archive = ZipFile(path)
    except (OSError, BadZipFile) as exc:
        raise VerificationError("archive is not a readable ZIP") from exc
    with archive:
        members = archive.infolist()
        if len(members) > MAX_MEMBERS:
            raise VerificationError("archive contains too many members")
        names = [member.filename for member in members]
        if len(names) != len(set(names)):
            raise VerificationError("archive contains duplicate member names")
        for name in names:
            safe_relative_path(name)
        manifest_names = [name for name in names if name.endswith("/manifest.json")]
        if len(manifest_names) != 1:
            raise VerificationError("expected exactly one packaged manifest.json")
        manifest_name = manifest_names[0]
        prefix = manifest_name.removesuffix("manifest.json")
        manifest_info = archive.getinfo(manifest_name)
        if manifest_info.file_size > MAX_MANIFEST_BYTES:
            raise VerificationError("manifest exceeds the size limit")
        manifest = parse_manifest(archive.read(manifest_info))

        def read_artifact(relative: str, expected_size: int) -> bytes:
            member_name = prefix + relative
            try:
                info = archive.getinfo(member_name)
            except KeyError as exc:
                raise VerificationError(f"{relative}: missing") from exc
            if info.is_dir() or info.file_size != expected_size:
                raise VerificationError(f"{relative}: size mismatch")
            return archive.read(info)

        count = verify_records(manifest, read_artifact)
        allowed = {prefix + name for name in HELPER_NAMES}
        allowed.update(prefix + str(record["path"]) for record in manifest["artifacts"])
        unexpected = sorted(
            name for name in names if not name.endswith("/") and name not in allowed
        )
        if unexpected:
            raise VerificationError(f"unexpected archive member: {unexpected[0]}")
        return str(manifest["case_id"]), count


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package", type=Path, help="Evidence ZIP or extracted directory")
    args = parser.parse_args()
    try:
        if args.package.is_dir():
            case_id, count = verify_directory(args.package)
        else:
            case_id, count = verify_zip(args.package)
    except (OSError, VerificationError) as exc:
        print(f"FAILED: {exc}", file=sys.stderr)
        return 1
    print(f"VERIFIED: {case_id} ({count} artifacts)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
