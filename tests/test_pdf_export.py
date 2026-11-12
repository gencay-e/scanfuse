import os
import re
from unittest.mock import patch

import pytest

from scanfuse.engine import OutputExistsError, ScanfuseEngine
from scanfuse.models import Evidence, Finding, Host


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
    ScanfuseEngine(str(tmp_path)).export_pdf(findings)
    # fpdf2 writes one uncompressed "/Type /Page" object per page, so no PDF reader is needed.
    data = (tmp_path / "report.pdf").read_bytes()
    pages = len(re.findall(rb"/Type\s*/Page(?![a-z])", data))
    assert pages > len(findings) + 1
