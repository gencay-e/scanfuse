from unittest.mock import patch

import pytest

from scanfuse.engine import ScanfuseEngine
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
    with pytest.raises(FileExistsError):
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
