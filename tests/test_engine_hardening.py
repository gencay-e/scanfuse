import json

import pytest

from scanfuse.engine import ScanfuseEngine, md_text
from scanfuse.html_report import render_report_fragment
from scanfuse.models import Evidence, Finding, Host, Observation


@pytest.mark.parametrize("data, expected", [({"results": []}, "semgrep"), ({"SchemaVersion": 2}, "trivy")])
def test_empty_scanner_detection(tmp_path, data, expected):
    path = tmp_path / "scan.json"
    path.write_text(json.dumps(data))
    assert ScanfuseEngine._detect_format(str(path)) == expected


def test_xml_detection_uses_root(tmp_path):
    path = tmp_path / "scan.xml"
    path.write_text('<other><!-- <nmaprun> --></other>')
    with pytest.raises(ValueError, match="XML root"):
        ScanfuseEngine._detect_format(str(path))


def test_manifest_unhashable_entries(tmp_path):
    engine = ScanfuseEngine(str(tmp_path))
    (tmp_path / ".scanfuse-manifest-json.json").write_text(json.dumps({"files": [[], {}]}))
    engine.export_json([], replace=True)
    assert (tmp_path / "report.json").exists()


def test_replace_recovers_from_deeply_nested_manifest(tmp_path):
    manifest = tmp_path / ".scanfuse-manifest-json.json"
    manifest.write_text("[" * 5000 + "]" * 5000, encoding="utf-8")
    ScanfuseEngine(str(tmp_path)).export_json([], replace=True)
    assert json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))["complete"] is True
    assert json.loads(manifest.read_text(encoding="utf-8"))["files"] == ["report.json"]


@pytest.mark.parametrize("fence", ["```", "~~~"])
def test_fenced_payload_preserved(fence):
    payload = f"{fence}\n<img src=x onerror=alert(1)> & test\n{fence}"
    fragment = render_report_fragment(md_text(payload))
    assert "&lt;img src=x onerror=alert(1)&gt; &amp; test" in fragment
    assert "&amp;lt;" not in fragment


def test_ipv6_filter_keeps_attributed_data(tmp_path):
    f = Finding(title="Rule", severity="Low", description="x", source_tool="test",
                hosts=[Host(ip="[2001:db8::1]")],
                observations=[Observation(host="2001:db8::1", location="/x", source_tool="test")],
                evidence=[Evidence(type="text", data="x", hosts=["2001:db8::1"])])
    result = ScanfuseEngine(str(tmp_path)).filter_by_host([f], "2001:db8::1")[0]
    assert result.observations and result.evidence


def test_unknown_host_does_not_match_wildcard(tmp_path):
    f = Finding(title="Rule", severity="Low", description="x", source_tool="test", hosts=[Host(ip="unknown")])
    assert ScanfuseEngine(str(tmp_path)).filter_by_host([f], "*") == []


def test_html_link_rewriting_preserves_evidence():
    fragment = render_report_fragment("```\n](secret.md)\n```\n\n[Finding](finding.md)")
    assert "](secret.md)" in fragment
    assert 'href="#finding"' in fragment


def test_html_link_rewriting_restricts_to_known_flat_finding_slugs():
    fragment = render_report_fragment(
        "[Known](finding.md) [Frag](finding.md#sec) [Nested](other/finding.md) [Missing](missing.md)",
        finding_slugs={"finding"},
    )
    assert fragment.count('href="#finding"') == 2
    assert 'href="other/finding.md"' in fragment
    assert 'href="#other/finding"' not in fragment
    assert 'href="missing.md"' in fragment
    assert 'href="#missing"' not in fragment


def test_index_title_single_line_and_reference_inert(tmp_path):
    f = Finding(title="First\nSecond", severity="Low", description="x", source_tool="test",
                references=["https://example.test/help", "https://example.test/>\n# Forged"])
    ScanfuseEngine(str(tmp_path)).export_findings([f])
    index = (tmp_path / "index.md").read_text(encoding="utf-8")
    assert "[First Second]" in index
    detail = (tmp_path / f"{f.slug}.md").read_text(encoding="utf-8")
    assert "\n# Forged" not in detail
    assert '<https://example.test/help>' in detail


def test_mismatched_fence_does_not_leave_raw_html():
    text = "````\n<img src=x onerror=alert(1)>\n```"
    assert "<img" not in md_text(text)


def test_evidence_code_appears_in_markdown_html_csv_and_pdf(tmp_path):
    import csv

    from pypdf import PdfReader

    finding = Finding(
        title="Code Issue", severity="High", description="Desc", source_tool="sarif",
        evidence=[Evidence(type="location", data="a.py:1", code="UNIQUE_SNIPPET_MARKER")],
    )
    md_dir = tmp_path / "md"
    ScanfuseEngine(str(md_dir)).export_findings([finding])
    assert "UNIQUE_SNIPPET_MARKER" in (md_dir / "code-issue.md").read_text(encoding="utf-8")
    assert "UNIQUE_SNIPPET_MARKER" in (md_dir / "report.html").read_text(encoding="utf-8")

    csv_dir = tmp_path / "csv"
    ScanfuseEngine(str(csv_dir)).export_csv([finding])
    with (csv_dir / "report.csv").open(newline="", encoding="utf-8") as handle:
        row = next(csv.DictReader(handle))
    assert "a.py:1\nUNIQUE_SNIPPET_MARKER" in row["Evidence"]

    pdf_dir = tmp_path / "pdf"
    ScanfuseEngine(str(pdf_dir)).export_pdf([finding])
    pdf_text = "\n".join(p.extract_text() for p in PdfReader(pdf_dir / "report.pdf").pages)
    assert "UNIQUE_SNIPPET_MARKER" in pdf_text


def test_unpaired_surrogates_in_input_fail_as_incomplete_import_without_crash(tmp_path):
    import json

    from typer.testing import CliRunner

    from scanfuse.cli import app

    good = tmp_path / "good.json"
    good.write_text(json.dumps({"template-id": "ok", "info": {"name": "Valid"}}), encoding="utf-8")
    bad = tmp_path / "surrogate.json"
    bad.write_text('{"template-id": "bad", "info": {"name": "x\\uD800y"}}', encoding="utf-8")
    out = tmp_path / "out"
    result = CliRunner().invoke(app, [str(good), str(bad), "-f", "nuclei", "-o", str(out)])
    assert result.exit_code == 1
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert "INCOMPLETE" in (out / "index.md").read_text(encoding="utf-8")
    assert (out / "valid.md").exists()
