import os
from unittest.mock import patch

import pytest
from pypdf import PdfReader

from scanfuse.engine import OutputExistsError, ScanfuseEngine
from scanfuse.models import Evidence, Finding, Host, SourceRecord


def test_pdf_export_creates_report(tmp_path):
    finding = Finding(
        title="SQL injection",
        severity="High",
        description="Unsafe query",
        source_tool="test",
    )
    ScanfuseEngine(str(tmp_path)).export_pdf([finding])
    content = (tmp_path / "report.pdf").read_bytes()
    assert content.startswith(b"%PDF")
    assert len(content) > 500


def test_pdf_export_with_all_finding_fields(tmp_path):
    finding = Finding(
        title="Complete finding test",
        severity="Critical",
        description="A full description with multiple paragraphs and unicode symbols: \u2714 \u2716.",
        remediation="Apply vendor patch 1.2.3 and update configs.",
        cvss_score=9.8,
        port="443",
        identifiers=["CVE-2026-9999", "CWE-89"],
        references=["https://example.com/advisory", "https://cve.mitre.org"],
        hosts=[Host(ip="192.168.1.10", hostname="srv1.local", os="Linux")],
        evidence=[
            Evidence(type="request", data="GET /api?id=1'"),
            Evidence(type="response", data="HTTP 500 Internal Error"),
        ],
        source_tool="nmap, nuclei",
    )
    ScanfuseEngine(str(tmp_path)).export_pdf([finding])
    content = (tmp_path / "report.pdf").read_bytes()
    assert content.startswith(b"%PDF")
    assert len(content) > 1000


def test_pdf_export_replace_guard(tmp_path):
    finding = Finding(
        title="Test",
        severity="Low",
        description="Desc",
        source_tool="test",
    )
    engine = ScanfuseEngine(str(tmp_path))
    engine.export_pdf([finding])
    with pytest.raises(OutputExistsError):
        engine.export_pdf([finding], replace=False)
    # With replace=True it succeeds
    engine.export_pdf([finding], replace=True)


def test_pdf_export_helvetica_fallback_without_unicode_font(tmp_path):
    finding = Finding(
        title="Fallback test",
        severity="Medium",
        description="Testing non-unicode core font fallback",
        source_tool="manual",
    )
    with patch("scanfuse.reporters.pdf._unicode_font_path", return_value=None):
        ScanfuseEngine(str(tmp_path)).export_pdf([finding], replace=True)
    content = (tmp_path / "report.pdf").read_bytes()
    assert content.startswith(b"%PDF")


def test_pdf_cli_exits_with_2_when_report_exists_and_0_with_replace(tmp_path):
    from typer.testing import CliRunner

    from scanfuse.cli import app

    source = os.path.join(os.path.dirname(__file__), "fixtures", "dummy_nmap_clean.xml")
    out = str(tmp_path / "out")
    runner = CliRunner()
    first = runner.invoke(app, [source, "-o", out, "--format-out", "pdf"])
    assert first.exit_code == 0, first.stdout
    second = runner.invoke(app, [source, "-o", out, "--format-out", "pdf"])
    assert second.exit_code == 2, second.stdout
    assert "--replace" in second.stdout
    third = runner.invoke(app, [source, "-o", out, "--format-out", "pdf", "--replace"])
    assert third.exit_code == 0, third.stdout


def test_a_finding_with_long_evidence_continues_on_further_pages(tmp_path):
    findings = [
        Finding(title=f"Finding {i}", severity="Low", description="d", source_tool="t",
                evidence=[Evidence(type="log", data="\n".join(f"line {n}" for n in range(400)))] if i == 0 else [])
        for i in range(2)
    ]
    with patch("scanfuse.reporters.pdf._unicode_font_path", return_value=None):
        ScanfuseEngine(str(tmp_path)).export_pdf(findings)
    report = PdfReader(tmp_path / "report.pdf")
    assert len(report.pages) > len(findings) + 1
    for number, page in enumerate(report.pages, 1):
        assert f"Page {number}/{len(report.pages)}" in page.extract_text()


def test_pdf_summary_import_errors_and_finding_metadata(tmp_path):
    finding = Finding(
        title="Web issue", severity="High", description="description", source_tool="zap",
        hosts=[Host(ip="192.0.2.5", hostname="web.example")],
        tags=["injection", "internet-facing"],
        sources=[SourceRecord(source_tool="nuclei", title="Template issue", severity="Medium",
                              description="also reported")],
    )
    with patch("scanfuse.reporters.pdf._unicode_font_path", return_value=None):
        ScanfuseEngine(str(tmp_path)).export_pdf(
            [finding], errors=[{"file": "missing.xml", "error": "parse failed"}]
        )
    text_content = "\n".join(page.extract_text() for page in PdfReader(tmp_path / "report.pdf").pages)
    for text in ("Severity", "Critical", "Import errors", "missing.xml", "parse failed",
                 "web.example", "injection", "Reported by: nuclei"):
        assert text in text_content


def test_pdf_large_evidence_is_capped_with_full_report_hint(tmp_path):
    finding = Finding(title="Large", severity="Low", description="d", source_tool="test",
                      evidence=[Evidence(type="log", data="x" * 2_000_000)])
    with patch("scanfuse.reporters.pdf._unicode_font_path", return_value=None):
        ScanfuseEngine(str(tmp_path)).export_pdf([finding])
    data = (tmp_path / "report.pdf").read_bytes()
    assert len(data) < 100_000
    text = "\n".join(page.extract_text() for page in PdfReader(tmp_path / "report.pdf").pages)
    assert "Evidence shortened; see full text in Markdown/JSON report." in text


def test_pdf_unicode_fallback_replaces_unsupported_glyphs(tmp_path):
    from scanfuse.reporters.pdf import _safe

    assert _safe("cafe\u0301 \u2714", is_unicode=False) == "cafe? ?"
