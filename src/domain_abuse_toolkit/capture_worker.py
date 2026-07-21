from __future__ import annotations

import base64
import binascii
import json
import sys
from pathlib import Path
from typing import Any


def _emit(payload: dict[str, Any], *, exit_code: int) -> None:
    sys.stdout.write(json.dumps(payload, separators=(",", ":")))
    raise SystemExit(exit_code)


def _bounded_int(value: Any, minimum: int, maximum: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError("invalid bound")
    if not minimum <= value <= maximum:
        raise ValueError("bound outside policy")
    return value


def _apply_resource_limits(request: dict[str, Any]) -> None:
    try:
        import resource
    except ImportError:
        return
    cpu = _bounded_int(request.get("cpu_limit_seconds"), 5, 120)
    nofile = _bounded_int(request.get("nofile_limit"), 64, 1024)
    file_size = _bounded_int(
        request.get("file_size_limit_bytes"), 256 * 1024, 32 * 1024 * 1024
    )
    resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu))
    resource.setrlimit(resource.RLIMIT_NOFILE, (nofile, nofile))
    resource.setrlimit(resource.RLIMIT_FSIZE, (file_size, file_size))


def main() -> None:
    stdio_output = False
    try:
        raw_request = sys.stdin.read(2 * 1024 * 1024 + 1)
        if len(raw_request) > 2 * 1024 * 1024:
            raise ValueError("request too large")
        request = json.loads(raw_request)
        if not isinstance(request, dict):
            raise ValueError("request must be an object")
        width = _bounded_int(request.get("viewport_width"), 320, 2560)
        viewport_height = _bounded_int(request.get("viewport_height"), 240, 2000)
        max_page_height = _bounded_int(request.get("max_page_height"), 240, 10000)
        timeout_ms = _bounded_int(request.get("navigation_timeout_ms"), 1000, 60000)
        _apply_resource_limits(request)
        encoded_source = request.get("source_base64")
        stdio_output = isinstance(encoded_source, str)
        source_path = Path.cwd() / "source.html"
        output_path = Path.cwd() / "desktop.png"
        source = (
            base64.b64decode(encoded_source, validate=True)
            if stdio_output
            else source_path.read_bytes()
        )
        if not source or len(source) > 1024 * 1024:
            raise ValueError("invalid source")
        html = source.decode("utf-8", errors="replace")
    except (OSError, ValueError, json.JSONDecodeError, binascii.Error):
        _emit({"ok": False, "code": "capture_input_invalid"}, exit_code=2)

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        _emit({"ok": False, "code": "capture_browser_unavailable"}, exit_code=3)

    stage = "launch"
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(
                headless=True,
                args=[
                    "--disable-background-networking",
                    "--disable-breakpad",
                    "--disable-component-update",
                    "--disable-default-apps",
                    "--disable-domain-reliability",
                    "--disable-features=MediaRouter,OptimizationHints,AutofillServerCommunication",
                    "--disable-sync",
                    "--host-resolver-rules=MAP * ~NOTFOUND",
                    "--metrics-recording-only",
                    "--no-first-run",
                    "--no-pings",
                ],
            )
            stage = "context"
            context = browser.new_context(
                accept_downloads=False,
                java_script_enabled=False,
                service_workers="block",
                viewport={"width": width, "height": viewport_height},
                locale="en-US",
                timezone_id="UTC",
                color_scheme="light",
            )
            context.clear_permissions()
            blocked_requests = {"count": 0}

            def block_request(route: Any) -> None:
                blocked_requests["count"] += 1
                route.abort("blockedbyclient")

            context.route("**/*", block_request)
            page = context.new_page()
            page.set_default_timeout(timeout_ms)
            page.on("dialog", lambda dialog: dialog.dismiss())
            page.on("download", lambda download: download.cancel())
            stage = "content"
            page.set_content(html, wait_until="domcontentloaded", timeout=timeout_ms)
            page.emulate_media(media="screen", reduced_motion="reduce")
            title = page.title()
            stage = "dimensions"
            dimensions = page.evaluate(
                """() => ({
                    width: Math.max(
                        document.documentElement.scrollWidth,
                        document.body?.scrollWidth || 0
                    ),
                    height: Math.max(
                        document.documentElement.scrollHeight,
                        document.body?.scrollHeight || 0
                    )
                })"""
            )
            capture_width = min(width, max(1, int(dimensions.get("width", width))))
            capture_height = min(
                max_page_height,
                max(viewport_height, int(dimensions.get("height", viewport_height))),
            )
            stage = "screenshot"
            page.screenshot(
                path=str(output_path),
                type="png",
                animations="disabled",
                caret="hide",
                clip={
                    "x": 0,
                    "y": 0,
                    "width": capture_width,
                    "height": capture_height,
                },
            )
            context.close()
            browser.close()
    except Exception as exc:
        _emit(
            {
                "ok": False,
                "code": "capture_render_failed",
                "stage": stage,
                "error_type": type(exc).__name__,
            },
            exit_code=4,
        )

    response = {
        "ok": True,
        "width": capture_width,
        "height": capture_height,
        "title": title[:300],
        "blocked_requests": blocked_requests["count"],
    }
    if stdio_output:
        try:
            response["screenshot_base64"] = base64.b64encode(
                output_path.read_bytes()
            ).decode("ascii")
        except OSError:
            _emit({"ok": False, "code": "capture_render_failed"}, exit_code=4)
    _emit(response, exit_code=0)


if __name__ == "__main__":
    main()
