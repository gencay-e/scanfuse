from pathlib import Path

from playwright.sync_api import sync_playwright

from scanfuse.engine import ScanfuseEngine
from scanfuse.models import Evidence, Finding


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
            page.reload()
            assert page.locator("#reportTheme").input_value() == theme
            assert page.evaluate("localStorage.getItem('scanfuse.report.theme')") == theme
        page.select_option("#reportTheme", "system")
        assert page.evaluate("localStorage.getItem('scanfuse.report.theme')") is None
        assert page.evaluate("document.documentElement.dataset.theme") is None
        for scheme, expected in [("dark", "rgb(13, 17, 23)"), ("light", "rgb(255, 255, 255)")]:
            page.emulate_media(color_scheme=scheme)
            assert page.locator("body").evaluate("element => getComputedStyle(element).backgroundColor") == expected
        page.reload()
        assert page.locator("#reportTheme").input_value() == "system"
        page.select_option("#filterSeverity", "High")
        assert page.locator(".finding-block:visible").count() == 1
        page.fill("#searchTitle", "missing")
        assert page.locator(".finding-block:visible").count() == 0
        page.fill("#searchTitle", "Unsafe")
        assert page.locator(".finding-block:visible").count() == 1
        assert requests == []
        assert errors == []
        browser.close()
