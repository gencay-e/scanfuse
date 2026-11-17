from collections.abc import Iterator
from contextlib import contextmanager
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

from playwright.sync_api import sync_playwright

from scanfuse.engine import ScanfuseEngine
from scanfuse.models import Evidence, Finding


class _QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:
        return


@contextmanager
def _local_http_root(directory: Path) -> Iterator[str]:
    handler = partial(_QuietHandler, directory=str(directory))
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address[:2]
        yield f"http://{host!s}:{port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_report_browser_controls_and_untrusted_input(tmp_path):
    payload = '<img src="https://example.test/track" onerror="window.injected=1"><script>window.injected=1</script>'
    engine = ScanfuseEngine(str(tmp_path))
    engine.export_findings([
        Finding(title="Unsafe " + payload, severity="High", description=payload, source_tool="test",
                evidence=[Evidence(type="raw", data=payload)]),
        Finding(title="Low finding", severity="Low", description="Safe", source_tool="test"),
    ])
    with sync_playwright() as p:
        edge = Path("C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe")
        browser = p.chromium.launch(executable_path=str(edge) if edge.exists() else None)
        try:
            page = browser.new_page()
            requests = []
            errors = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.on("request", lambda request: requests.append(request.url) if request.url.startswith(("http:", "https:")) else None)
            page.goto((tmp_path / "report.html").as_uri())
            assert page.locator(".finding-block").count() == 2
            assert page.evaluate("window.injected") is None
            assert page.locator("script").count() == 1
            for theme in ["light", "dark"]:
                page.select_option("#reportTheme", theme)
                assert page.evaluate("document.documentElement.dataset.theme") == theme
                expected = "rgb(255, 255, 255)" if theme == "light" else "rgb(13, 17, 23)"
                assert page.locator("body").evaluate("element => getComputedStyle(element).backgroundColor") == expected
            page.select_option("#reportTheme", "system")
            assert page.evaluate("document.documentElement.dataset.theme") is None
            for scheme, expected in [("dark", "rgb(13, 17, 23)"), ("light", "rgb(255, 255, 255)")]:
                page.emulate_media(color_scheme=scheme)
                assert page.locator("body").evaluate("element => getComputedStyle(element).backgroundColor") == expected
            page.select_option("#filterSeverity", "High")
            assert page.locator(".finding-block:visible").count() == 1
            page.fill("#searchTitle", "missing")
            assert page.locator(".finding-block:visible").count() == 0
            page.fill("#searchTitle", "Unsafe")
            assert page.locator(".finding-block:visible").count() == 1
            assert requests == []
            assert errors == []

            # file:// uses an opaque origin where Chromium is not required to persist localStorage across reloads.
            with _local_http_root(tmp_path) as base_url:
                external_requests = []
                http_page = browser.new_page()
                http_page.on("pageerror", lambda error: errors.append(str(error)))
                http_page.on(
                    "request",
                    lambda request: external_requests.append(request.url)
                    if request.url.startswith(("http:", "https:")) and not request.url.startswith(base_url)
                    else None,
                )
                http_page.goto(f"{base_url}/report.html")
                for theme in ["light", "dark"]:
                    http_page.select_option("#reportTheme", theme)
                    http_page.reload()
                    assert http_page.locator("#reportTheme").input_value() == theme
                    assert http_page.evaluate("localStorage.getItem('scanfuse.report.theme')") == theme
                http_page.select_option("#reportTheme", "system")
                http_page.reload()
                assert http_page.locator("#reportTheme").input_value() == "system"
                assert http_page.evaluate("localStorage.getItem('scanfuse.report.theme')") is None
                assert external_requests == []
                assert errors == []
        finally:
            browser.close()
