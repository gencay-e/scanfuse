from html.parser import HTMLParser

import pytest

from scanfuse.engine import ScanfuseEngine
from scanfuse.models import Evidence, Finding


class ReportHTML(HTMLParser):
    def __init__(self, text):
        super().__init__()
        self.elements = []
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        self.elements.append((tag, dict(attrs)))


@pytest.mark.parametrize("payload", [
    "[click](javascript:alert%281%29)",
    "[click](JaVaScRiPt:alert%281%29)",
    "[click](data:text/html;base64,PHNjcmlwdD4=)",
    "[click](vbscript:msgbox%281%29)",
    "![tracker](https://example.test/track)",
])
def test_scanner_text_cannot_create_active_html(tmp_path, payload):
    finding = Finding(title=payload, description=payload, remediation=payload,
                      severity="High", source_tool="test")
    ScanfuseEngine(str(tmp_path)).export_findings([finding])
    parsed = ReportHTML((tmp_path / "report.html").read_text(encoding="utf-8"))
    for tag, attrs in parsed.elements:
        assert tag not in {"img", "iframe", "svg", "object", "embed"}
        assert not any(name.startswith("on") for name in attrs)
        for name in ("href", "src"):
            assert not attrs.get(name, "").lower().startswith(("javascript:", "vbscript:", "data:"))
    assert sum(tag == "script" for tag, _ in parsed.elements) == 1


def test_custom_markdown_is_sanitized_and_report_attributes_escape_titles(tmp_path):
    templates = tmp_path / "templates"
    templates.mkdir()
    (templates / "finding.md.j2").write_text(
        '<script>alert(1)</script><svg onload="alert(2)"></svg>'
        '<a href="javascript:alert(3)" onclick="alert(4)">click</a>'
        '<p id="searchTitle" style="color:red">Safe text</p>', encoding="utf-8")
    (templates / "index.md.j2").write_text('<iframe src="https://example.test"></iframe>', encoding="utf-8")
    title = 'Title &quot; onmouseover=&quot;alert(5) <script>alert(6)</script>'
    finding = Finding(title=title, description="Description", severity="Low", source_tool="test")
    output = tmp_path / "report"
    ScanfuseEngine(str(output), str(templates)).export_findings([finding])
    text = (output / "report.html").read_text(encoding="utf-8")
    parsed = ReportHTML(text)
    assert "Safe text" in text
    assert sum(tag == "script" for tag, _ in parsed.elements) == 1
    assert not any(tag in {"svg", "iframe"} for tag, _ in parsed.elements)
    for _, attrs in parsed.elements:
        assert not any(name.startswith("on") for name in attrs)
        assert "style" not in attrs
        assert not attrs.get("href", "").startswith("javascript:")
    block = next(attrs for _, attrs in parsed.elements if attrs.get("class") == "finding-block")
    assert block["data-title"] == title.lower()
    assert sum(attrs.get("id") == "searchTitle" for _, attrs in parsed.elements) == 1


def test_html_preserves_tables_links_evidence_and_filter_controls(tmp_path):
    finding = Finding(title="Safe finding", severity="High", source_tool="test",
                      description="[Docs](https://example.test/docs)\n\n**Important**",
                      evidence=[Evidence(type="response", data='<script>alert(1)</script>\n```')])
    ScanfuseEngine(str(tmp_path)).export_findings([finding])
    text = (tmp_path / "report.html").read_text(encoding="utf-8")
    parsed = ReportHTML(text)
    assert any(tag == "table" for tag, _ in parsed.elements)
    assert any(tag == "strong" for tag, _ in parsed.elements)
    assert any(attrs.get("href") == "https://example.test/docs" for _, attrs in parsed.elements)
    assert any(attrs.get("href") == "#safe-finding" for _, attrs in parsed.elements)
    assert any(attrs.get("id") == "safe-finding" for _, attrs in parsed.elements)
    assert any(attrs.get("id") == "searchTitle" for _, attrs in parsed.elements)
    assert any(attrs.get("id") == "filterSeverity" for _, attrs in parsed.elements)
    # Evidence is shown as it was reported: escaped once, and the backtick line is kept.
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in text
    assert "&amp;lt;" not in text
    assert "<code>&lt;script&gt;alert(1)&lt;/script&gt;\n```\n</code>" in text
    assert "function filterFindings()" in text
