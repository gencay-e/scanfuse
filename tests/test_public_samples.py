"""Real scanner output from the public DefectDojo sample repository (MIT license).

See tests/fixtures/public/README.md for the origin of each file. Every file is read with automatic
format detection. The number of findings is compared with a count made by independent code, and the
exports of a merged report are checked for loss.
"""
import csv
import json
import re
from pathlib import Path

import defusedxml.ElementTree as ET
import pytest
from typer.testing import CliRunner

from scanfuse.cli import app
from scanfuse.engine import ScanfuseEngine
from scanfuse.utils import deduplicate_findings

PUBLIC = Path(__file__).parent / "fixtures" / "public"
FILES = sorted(p for p in PUBLIC.iterdir() if p.suffix in {".xml", ".json", ".nessus"})
runner = CliRunner(env={"COLUMNS": "400"})


def independent_count(path: Path) -> int:
    """Number of findings in a file, counted with plain XML/JSON code, not with the scanfuse parsers."""
    raw = path.read_text(encoding="utf-8")
    if path.suffix == ".json":
        data = json.loads(raw)
        results = data if isinstance(data, list) else data.get("Results") or []
        return sum(len(r.get(key) or []) for r in results for key in ("Vulnerabilities", "Misconfigurations", "Secrets"))
    root = ET.fromstring(re.sub(r"<!DOCTYPE.*?\]>", "", raw, flags=re.S))
    if root.tag == "nmaprun":
        return sum(
            1
            for host in root.iter("host")
            if (host.find("status") is None or host.find("status").get("state") == "up")
            for port in host.iter("port")
            if port.find("state") is not None and port.find("state").get("state") == "open"
        )
    return {"OWASPZAPReport": sum(1 for _ in root.iter("alertitem")),
            "NessusClientData_v2": sum(1 for _ in root.iter("ReportItem")),
            "issues": sum(1 for _ in root.iter("issue"))}[root.tag]


def read(path: Path, tmp_path: Path):
    return ScanfuseEngine(str(tmp_path)).process_file(str(path), "auto")


def test_the_fixture_folder_is_not_empty():
    assert len(FILES) == 8


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_every_finding_of_a_real_file_is_read(path, tmp_path):
    findings = read(path, tmp_path)
    assert len(findings) == independent_count(path) > 0


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_titles_are_real_and_every_finding_has_a_host(path, tmp_path):
    findings = read(path, tmp_path)
    assert not [f.title for f in findings if f.title.lower().startswith(("unknown", "unnamed"))]
    assert all(f.hosts for f in findings)
    assert all(f.severity in {"Critical", "High", "Medium", "Low", "Info"} for f in findings)


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_merging_keeps_every_host_and_evidence(path, tmp_path):
    findings = read(path, tmp_path)
    merged = deduplicate_findings(findings)
    assert {(h.ip, h.hostname) for f in merged for h in f.hosts} == {(h.ip, h.hostname) for f in findings for h in f.hosts}
    before = {(e.type, e.data) for f in findings for e in f.evidence}
    after = {(e.type, e.data) for f in merged for e in f.evidence}
    assert after == before


@pytest.mark.parametrize("fmt", ["json", "csv", "markdown"])
def test_all_public_files_in_one_report_in_every_format(tmp_path, fmt):
    out = tmp_path / "out"
    result = runner.invoke(app, [*map(str, FILES), "-o", str(out), "--format-out", fmt])
    assert result.exit_code == 0, result.stdout
    expected = deduplicate_findings([f for p in FILES for f in read(p, tmp_path)])
    if fmt == "json":
        data = json.loads((out / "report.json").read_text(encoding="utf-8"))
        assert data["complete"] is True and len(data["findings"]) == len(expected)
    elif fmt == "csv":
        with (out / "report.csv").open(newline="", encoding="utf-8") as stream:
            assert len(list(csv.reader(stream))) - 1 == len(expected)
    else:
        assert f"Total Findings: {len(expected)}" in (out / "index.md").read_text(encoding="utf-8")
        assert (out / "report.html").stat().st_size > 10_000


def test_old_zap_format_without_name_and_instances_is_understood(tmp_path):
    findings = read(PUBLIC / "zaproxy-demo-site_1.4.0.1.xml", tmp_path)
    assert len({f.title for f in findings}) > 5
    assert any("X-Frame-Options" in f.title for f in findings)
    with_url = [f for f in findings if f.evidence and f.evidence[0].data.startswith("Request:")]
    assert len(with_url) == len(findings), "the affected URL of an old-format alert must be kept as evidence"
    # Every ZAP 1.x alertitem names one URL. The same alert at another path stays a separate finding.
    assert all(f.places() for f in findings)
    merged = deduplicate_findings(findings)
    assert len(merged) <= len(findings)
    assert len({(f.title, f.places()) for f in findings}) == len(merged)


def test_burp_file_with_a_long_dtd_is_detected_and_keeps_text_cwe_and_links(tmp_path):
    findings = read(PUBLIC / "burpvulns_v2_1_02.xml", tmp_path)
    assert findings[0].source_tool == "burp"
    for f in findings:
        assert "<p>" not in f.description and "<br>" not in f.description and "&amp;" not in f.description
    hsts = next(f for f in findings if f.title.startswith("Strict transport security"))
    assert "CWE-523" in hsts.identifiers
    assert hsts.references and all(u.startswith("http") for u in hsts.references)
    assert 'HTTP Strict Transport Security' in hsts.remediation or "HSTS" in hsts.remediation
    assert "&quot;" not in hsts.remediation


def test_old_trivy_list_format_is_detected(tmp_path):
    findings = read(PUBLIC / "trivy_mix.json", tmp_path)
    assert {f.source_tool for f in findings} == {"trivy"}
    assert len(findings) == 6
    assert all(any(i.startswith("CVE-") for i in f.identifiers) for f in findings)


def test_trivy_keeps_cwe_and_reference_links(tmp_path):
    findings = read(PUBLIC / "k-client_trivy-report.json", tmp_path)
    assert sum(any(i.startswith("CWE-") for i in f.identifiers) for f in findings) >= 20
    assert all(f.references for f in findings)


def test_nessus_synopsis_and_links_are_kept_and_not_applicable_solutions_are_dropped(tmp_path):
    findings = read(PUBLIC / "nessus_v_unknown_two_smallest_hosts.nessus", tmp_path)
    info = next(f for f in findings if f.title == "Nessus Scan Information")
    assert info.description.startswith("Information about the Nessus scan.")
    assert info.remediation is None
    assert any(f.references for f in findings)


def test_references_appear_in_markdown_html_and_csv(tmp_path):
    out = tmp_path / "out"
    source = str(PUBLIC / "k-client_trivy-report.json")
    assert runner.invoke(app, [source, "-o", str(out)]).exit_code == 0
    page = next(p for p in out.glob("*.md") if p.name != "index.md")
    assert "## References" in page.read_text(encoding="utf-8")
    assert 'href="https://avd.aquasec.com/' in (out / "report.html").read_text(encoding="utf-8")
    out2 = tmp_path / "out2"
    assert runner.invoke(app, [source, "-o", str(out2), "--format-out", "csv"]).exit_code == 0
    with (out2 / "report.csv").open(newline="", encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream))
    assert rows[0]["References"].startswith("http")
