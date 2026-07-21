from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import shutil
import signal
import subprocess
import tempfile
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from domain_abuse_toolkit.models import (
    CollectorError,
    CollectorObservation,
    CollectorResult,
    CollectorStatus,
    NormalizedTarget,
)
from domain_abuse_toolkit.services.collectors import CollectorOutput
from domain_abuse_toolkit.services.evidence import PendingArtifact
from domain_abuse_toolkit.services.html_resources import inline_collected_stylesheets

_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
_HTML_MEDIA_TYPES = {"text/html", "application/xhtml+xml"}
WorkerRunner = Callable[[Path, Path, dict[str, Any], float], dict[str, Any]]


class CaptureWorkerError(ValueError):
    def __init__(self, code: str, message: str, *, retryable: bool = False) -> None:
        super().__init__(message)
        self.code = code
        self.retryable = retryable


class ScreenshotCollector:
    """Render bounded HTTP evidence in a separate, network-blocked browser worker."""

    version = "1.1"

    def __init__(
        self,
        *,
        runner: WorkerRunner | None = None,
        timeout_seconds: float = 25.0,
        max_input_bytes: int = 256 * 1024,
        max_render_input_bytes: int = 1024 * 1024,
        max_output_bytes: int = 10 * 1024 * 1024,
        viewport_width: int = 1440,
        viewport_height: int = 1000,
        max_page_height: int = 6000,
    ) -> None:
        self.runner = runner or run_capture_worker
        self.timeout_seconds = timeout_seconds
        self.max_input_bytes = max_input_bytes
        self.max_render_input_bytes = max_render_input_bytes
        self.max_output_bytes = max_output_bytes
        self.viewport_width = viewport_width
        self.viewport_height = viewport_height
        self.max_page_height = max_page_height

    def collect(
        self,
        target: NormalizedTarget,
        snapshot_id: str,
        source_artifact: PendingArtifact | None,
        stylesheet_artifacts: list[PendingArtifact] | None = None,
    ) -> CollectorOutput:
        started_at = datetime.now(UTC)
        if source_artifact is None:
            return self._result(
                started_at,
                CollectorStatus.SKIPPED,
                errors=[
                    CollectorError(
                        code="capture_source_missing",
                        message="No complete HTML response was available for offline rendering.",
                    )
                ],
            )
        if source_artifact.media_type not in _HTML_MEDIA_TYPES:
            return self._result(
                started_at,
                CollectorStatus.SKIPPED,
                errors=[
                    CollectorError(
                        code="capture_source_unsupported",
                        message="The final bounded HTTP response was not HTML.",
                    )
                ],
            )
        if source_artifact.metadata.get("truncated"):
            return self._result(
                started_at,
                CollectorStatus.SKIPPED,
                errors=[
                    CollectorError(
                        code="capture_source_truncated",
                        message="A truncated HTTP response is not rendered as visual evidence.",
                    )
                ],
            )
        if len(source_artifact.content) > self.max_input_bytes:
            return self._result(
                started_at,
                CollectorStatus.FAILED,
                errors=[
                    CollectorError(
                        code="capture_input_too_large",
                        message="The HTML evidence exceeded the capture input limit.",
                    )
                ],
            )

        rendered_source, stylesheets_inlined = inline_collected_stylesheets(
            source_artifact.content,
            str(source_artifact.metadata.get("requested_url", target.normalized_url)),
            stylesheet_artifacts or [],
        )
        if len(rendered_source) > self.max_render_input_bytes:
            return self._result(
                started_at,
                CollectorStatus.FAILED,
                errors=[
                    CollectorError(
                        code="capture_render_input_too_large",
                        message="The HTML and collected styles exceeded the render limit.",
                    )
                ],
            )

        request = {
            "viewport_width": self.viewport_width,
            "viewport_height": self.viewport_height,
            "max_page_height": self.max_page_height,
            "navigation_timeout_ms": max(1000, int(self.timeout_seconds * 700)),
            "cpu_limit_seconds": max(5, int(self.timeout_seconds)),
            "nofile_limit": 1024,
            "file_size_limit_bytes": 32 * 1024 * 1024,
            "output_limit_bytes": self.max_output_bytes,
        }
        try:
            with tempfile.TemporaryDirectory(prefix="dat-capture-") as temporary:
                workspace = Path(temporary)
                source_path = workspace / "source.html"
                output_path = workspace / "desktop.png"
                source_path.write_bytes(rendered_source)
                metadata = self.runner(
                    source_path, output_path, request, self.timeout_seconds
                )
                screenshot = self._read_screenshot(output_path)
        except CaptureWorkerError as exc:
            return self._result(
                started_at,
                CollectorStatus.FAILED,
                errors=[
                    CollectorError(
                        code=exc.code, message=str(exc), retryable=exc.retryable
                    )
                ],
            )
        except OSError:
            return self._result(
                started_at,
                CollectorStatus.FAILED,
                errors=[
                    CollectorError(
                        code="capture_worker_failed",
                        message="The isolated capture workspace could not be processed.",
                    )
                ],
            )

        output_path = f"10_snapshots/{snapshot_id}/capture/desktop.png"
        artifact = PendingArtifact(
            relative_path=output_path,
            content=screenshot,
            media_type="image/png",
            source="offline browser rendering of bounded HTTP evidence",
            metadata={
                "collector": "screenshot",
                "collector_version": self.version,
                "requested_url": source_artifact.metadata.get(
                    "requested_url", target.normalized_url
                ),
                "render_mode": "offline_static",
                "javascript": "disabled",
                "network": "blocked",
                "viewport_width": _bounded_int(metadata.get("width"), 1, 10000),
                "captured_height": _bounded_int(metadata.get("height"), 1, 10000),
                "stylesheets_inlined": stylesheets_inlined,
            },
            classification="derived",
            derived_from=(
                source_artifact.relative_path,
                *(artifact.relative_path for artifact in stylesheet_artifacts or []),
            ),
        )
        observations = [
            CollectorObservation(
                category="capture", name="mode", value="offline_static"
            ),
            CollectorObservation(
                category="capture", name="javascript", value="disabled"
            ),
            CollectorObservation(category="capture", name="network", value="blocked"),
            CollectorObservation(
                category="capture",
                name="source_artifact",
                value=source_artifact.relative_path,
            ),
            CollectorObservation(
                category="capture",
                name="dimensions",
                value=(
                    f"{_bounded_int(metadata.get('width'), 1, 10000)}x"
                    f"{_bounded_int(metadata.get('height'), 1, 10000)}"
                ),
            ),
            CollectorObservation(
                category="capture",
                name="image_sha256",
                value=hashlib.sha256(screenshot).hexdigest(),
            ),
            CollectorObservation(
                category="capture",
                name="stylesheets_inlined",
                value=str(stylesheets_inlined),
            ),
        ]
        title = _safe_text(metadata.get("title"), limit=300)
        if title:
            observations.append(
                CollectorObservation(category="capture", name="document_title", value=title)
            )
        return self._result(
            started_at,
            CollectorStatus.COMPLETE,
            observations=observations,
            artifacts=[artifact],
        )

    def _read_screenshot(self, output_path: Path) -> bytes:
        try:
            size = output_path.stat().st_size
        except OSError as exc:
            raise CaptureWorkerError(
                "capture_output_missing", "The browser worker produced no screenshot."
            ) from exc
        if size <= len(_PNG_SIGNATURE) or size > self.max_output_bytes:
            raise CaptureWorkerError(
                "capture_output_invalid",
                "The browser screenshot was empty or exceeded its size limit.",
            )
        content = output_path.read_bytes()
        if not content.startswith(_PNG_SIGNATURE):
            raise CaptureWorkerError(
                "capture_output_invalid", "The browser worker output was not a PNG image."
            )
        return content

    def _result(
        self,
        started_at: datetime,
        status: CollectorStatus,
        *,
        observations: list[CollectorObservation] | None = None,
        errors: list[CollectorError] | None = None,
        artifacts: list[PendingArtifact] | None = None,
    ) -> CollectorOutput:
        pending = artifacts or []
        return CollectorOutput(
            result=CollectorResult(
                collector="screenshot",
                version=self.version,
                status=status,
                started_at=started_at,
                finished_at=datetime.now(UTC),
                observations=observations or [],
                artifacts=[artifact.relative_path for artifact in pending],
                errors=errors or [],
            ),
            artifacts=pending,
        )


def run_capture_worker(
    source_path: Path,
    output_path: Path,
    request: dict[str, Any],
    timeout_seconds: float,
) -> dict[str, Any]:
    if source_path.parent != output_path.parent:
        raise CaptureWorkerError(
            "capture_worker_failed", "The capture workspace was invalid."
        )
    docker_command = os.environ.get("DAT_CAPTURE_DOCKER_COMMAND") or shutil.which(
        "docker"
    )
    if not docker_command:
        raise CaptureWorkerError(
            "capture_browser_unavailable",
            "The isolated Docker capture runtime is not available.",
        )
    return _run_docker_worker(
        docker_command,
        source_path,
        output_path,
        request,
        timeout_seconds,
    )


def _run_docker_worker(
    docker_command: str,
    source_path: Path,
    output_path: Path,
    request: dict[str, Any],
    timeout_seconds: float,
) -> dict[str, Any]:
    container_name = f"dat-capture-{uuid.uuid4().hex}"
    image = os.environ.get(
        "DAT_CAPTURE_DOCKER_IMAGE", "domain-abuse-toolkit-capture:1.0"
    )
    docker_request = dict(request)
    docker_request["source_base64"] = base64.b64encode(
        source_path.read_bytes()
    ).decode("ascii")
    command = [
        docker_command,
        "run",
        "--rm",
        "--interactive",
        f"--name={container_name}",
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--pids-limit=128",
        "--memory=1536m",
        "--cpus=1.0",
        "--shm-size=256m",
        "--tmpfs=/tmp:rw,nosuid,nodev,noexec,size=64m",
        "--user=pwuser",
        image,
    ]
    process = subprocess.Popen(
        command,
        cwd=source_path.parent,
        env={
            name: value
            for name in ("HOME", "LANG", "PATH")
            if (value := os.environ.get(name))
        },
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        stdout, _stderr = process.communicate(
            json.dumps(docker_request, separators=(",", ":")),
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        _terminate_process(process)
        subprocess.run(
            [docker_command, "rm", "--force", container_name],
            check=False,
            capture_output=True,
            timeout=10,
        )
        raise CaptureWorkerError(
            "capture_timeout",
            "The isolated browser capture exceeded its deadline.",
            retryable=True,
        ) from exc
    maximum_stdout = int(request["output_limit_bytes"]) * 2
    response = _parse_worker_response(
        process.returncode, stdout, maximum=maximum_stdout
    )
    encoded = response.pop("screenshot_base64", None)
    if not isinstance(encoded, str):
        raise CaptureWorkerError(
            "capture_output_missing", "The browser worker produced no screenshot."
        )
    try:
        screenshot = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise CaptureWorkerError(
            "capture_output_invalid", "The browser worker output was not a PNG image."
        ) from exc
    output_path.write_bytes(screenshot)
    return response


def _parse_worker_response(
    returncode: int, stdout: str, *, maximum: int
) -> dict[str, Any]:
    if len(stdout) > maximum:
        raise CaptureWorkerError(
            "capture_worker_failed", "The browser worker returned an invalid result."
        )
    try:
        response = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise CaptureWorkerError(
            "capture_worker_failed", "The browser worker returned no valid result."
        ) from exc
    if not isinstance(response, dict):
        raise CaptureWorkerError(
            "capture_worker_failed", "The browser worker result was invalid."
        )
    if returncode != 0 or response.get("ok") is not True:
        code = response.get("code")
        allowed_code = (
            code
            if code
            in {
                "capture_browser_unavailable",
                "capture_input_invalid",
                "capture_render_failed",
            }
            else "capture_worker_failed"
        )
        messages = {
            "capture_browser_unavailable": (
                "The optional Chromium capture runtime is not installed."
            ),
            "capture_input_invalid": "The bounded HTML capture input was invalid.",
            "capture_render_failed": "The offline browser rendering failed.",
            "capture_worker_failed": "The isolated browser worker failed.",
        }
        raise CaptureWorkerError(allowed_code, messages[allowed_code])
    return response


def _terminate_process(process: subprocess.Popen[str]) -> None:
    if os.name == "posix":
        os.killpg(process.pid, signal.SIGKILL)
    else:
        process.kill()
    process.communicate()


def _safe_text(value: Any, *, limit: int) -> str:
    if not isinstance(value, str):
        return ""
    return "".join(
        character if ord(character) >= 32 and ord(character) != 127 else " "
        for character in value
    )[:limit]


def _bounded_int(value: Any, minimum: int, maximum: int) -> int:
    if not isinstance(value, int):
        return minimum
    return min(maximum, max(minimum, value))
