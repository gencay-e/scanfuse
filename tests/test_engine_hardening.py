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
