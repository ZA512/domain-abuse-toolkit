import hashlib
from pathlib import Path

from domain_abuse_toolkit.models import CollectorStatus
from domain_abuse_toolkit.security.targets import normalize_target
from domain_abuse_toolkit.services.evidence import PendingArtifact
from domain_abuse_toolkit.services.screenshot_collector import (
    CaptureWorkerError,
    ScreenshotCollector,
    run_capture_worker,
)


def _source(*, truncated: bool = False, content: bytes = b"<h1>Evidence</h1>") -> PendingArtifact:
    return PendingArtifact(
        relative_path="10_snapshots/SNP-TEST/http/00-body.bin",
        content=content,
        media_type="text/html",
        source="synthetic HTTP evidence",
        metadata={
            "collector": "http",
            "requested_url": "https://example.com/",
            "truncated": truncated,
        },
    )


def successful_runner(
    source_path: Path,
    output_path: Path,
    request: dict[str, object],
    timeout_seconds: float,
) -> dict[str, object]:
    assert source_path.read_bytes() == b"<h1>Evidence</h1>"
    assert request["viewport_width"] == 1440
    assert timeout_seconds > 0
    output_path.write_bytes(b"\x89PNG\r\n\x1a\nsynthetic")
    return {"ok": True, "width": 1440, "height": 1000, "title": "Evidence"}


def test_screenshot_collector_creates_a_traced_derived_png() -> None:
    output = ScreenshotCollector(runner=successful_runner).collect(
        normalize_target("https://example.com/"), "SNP-TEST", _source()
    )

    assert output.result.status == CollectorStatus.COMPLETE
    assert output.result.artifacts == [
        "10_snapshots/SNP-TEST/capture/desktop.png"
    ]
    observations = {item.name: item.value for item in output.result.observations}
    assert observations["network"] == "blocked"
    assert observations["image_sha256"] == hashlib.sha256(
        b"\x89PNG\r\n\x1a\nsynthetic"
    ).hexdigest()
    assert output.artifacts[0].classification == "derived"
    assert output.artifacts[0].derived_from == (
        "10_snapshots/SNP-TEST/http/00-body.bin",
    )


def test_screenshot_collector_inlines_collected_css_without_browser_network() -> None:
    stylesheet = PendingArtifact(
        relative_path="10_snapshots/SNP-TEST/http/styles/00.css",
        content=b"body { color: rgb(1, 2, 3); }",
        media_type="text/css",
        source="synthetic stylesheet evidence",
        metadata={
            "resource_type": "stylesheet",
            "stylesheet_url": "https://example.com/app.css",
            "truncated": False,
        },
    )

    def styled_runner(
        source_path: Path,
        output_path: Path,
        _request: dict[str, object],
        _timeout_seconds: float,
    ) -> dict[str, object]:
        source = source_path.read_text(encoding="utf-8")
        assert '<style data-dat-stylesheet="https://example.com/app.css">' in source
        assert "body { color: rgb(1, 2, 3); }" in source
        assert 'rel="stylesheet"' not in source
        output_path.write_bytes(b"\x89PNG\r\n\x1a\nsynthetic")
        return {"ok": True, "width": 1440, "height": 1000, "title": "Styled"}

    output = ScreenshotCollector(runner=styled_runner).collect(
        normalize_target("https://example.com/"),
        "SNP-TEST",
        _source(content=b'<link rel="stylesheet" href="/app.css"><h1>Evidence</h1>'),
        [stylesheet],
    )

    observations = {item.name: item.value for item in output.result.observations}
    assert output.result.status == CollectorStatus.COMPLETE
    assert observations["stylesheets_inlined"] == "1"
    assert output.artifacts[0].derived_from == (
        "10_snapshots/SNP-TEST/http/00-body.bin",
        "10_snapshots/SNP-TEST/http/styles/00.css",
    )


def test_screenshot_collector_skips_missing_or_truncated_html() -> None:
    collector = ScreenshotCollector(runner=successful_runner)
    target = normalize_target("https://example.com/")

    missing = collector.collect(target, "SNP-TEST", None)
    truncated = collector.collect(target, "SNP-TEST", _source(truncated=True))

    assert missing.result.status == CollectorStatus.SKIPPED
    assert missing.result.errors[0].code == "capture_source_missing"
    assert truncated.result.status == CollectorStatus.SKIPPED
    assert truncated.result.errors[0].code == "capture_source_truncated"


def test_screenshot_collector_rejects_oversized_input_before_worker() -> None:
    called = False

    def runner(*_args, **_kwargs):  # type: ignore[no-untyped-def]
        nonlocal called
        called = True
        return {}

    output = ScreenshotCollector(runner=runner, max_input_bytes=16).collect(
        normalize_target("https://example.com/"),
        "SNP-TEST",
        _source(content=b"<html>too large</html>"),
    )

    assert output.result.status == CollectorStatus.FAILED
    assert output.result.errors[0].code == "capture_input_too_large"
    assert called is False


def test_screenshot_worker_failure_is_structured_without_worker_details() -> None:
    def runner(*_args, **_kwargs):  # type: ignore[no-untyped-def]
        raise CaptureWorkerError(
            "capture_browser_unavailable", "The optional browser is unavailable."
        )

    output = ScreenshotCollector(runner=runner).collect(
        normalize_target("https://example.com/"), "SNP-TEST", _source()
    )

    assert output.result.status == CollectorStatus.FAILED
    assert output.result.errors[0].code == "capture_browser_unavailable"
    assert output.artifacts == []


def test_docker_worker_uses_a_networkless_read_only_container(
    tmp_path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    fake_docker = tmp_path / "docker"
    fake_docker.write_text(
        """#!/usr/bin/env python3
import base64
import json
import sys

required = {'--network=none', '--read-only', '--cap-drop=ALL'}
if not required.issubset(set(sys.argv)):
    raise SystemExit(9)
request = json.load(sys.stdin)
if base64.b64decode(request['source_base64']) != b'<h1>Evidence</h1>':
    raise SystemExit(8)
print(json.dumps({
    'ok': True,
    'width': 1440,
    'height': 1000,
    'title': 'Evidence',
    'screenshot_base64': base64.b64encode(b'\\x89PNG\\r\\n\\x1a\\nsynthetic').decode(),
}))
""",
        encoding="utf-8",
    )
    fake_docker.chmod(0o755)
    monkeypatch.setenv("DAT_CAPTURE_DOCKER_COMMAND", str(fake_docker))
    source_path = tmp_path / "source.html"
    output_path = tmp_path / "desktop.png"
    source_path.write_bytes(b"<h1>Evidence</h1>")

    response = run_capture_worker(
        source_path,
        output_path,
        {
            "file_size_limit_bytes": 32 * 1024 * 1024,
            "output_limit_bytes": 1024 * 1024,
        },
        10,
    )

    assert response["title"] == "Evidence"
    assert output_path.read_bytes().startswith(b"\x89PNG")
