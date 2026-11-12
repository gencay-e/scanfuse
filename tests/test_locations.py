"""Observations (host, method, location) must reach every output format."""
import csv
import json
from unittest.mock import patch

from typer.testing import CliRunner

from scanfuse.cli import app
from scanfuse.engine import ScanfuseEngine
from scanfuse.models import Evidence, Finding, Host, Observation
from scanfuse.reporters import pdf as pdf_module
from scanfuse.utils import RESERVED_SLUGS, deduplicate_findings, slugify, unique_slug


def _obs(host, method, location, tool="zap"):
    return Observation(host=host, method=method, location=location, source_tool=tool)


def _two_findings():
    return [
        Finding(title="SQL Injection", severity="High", description="d", source_tool="zap",
                hosts=[Host(ip="10.0.0.1")], observations=[_obs("10.0.0.1", "POST", "/login")]),
        Finding(title="SQL Injection", severity="High", description="d", source_tool="zap",
                hosts=[Host(ip="10.0.0.1")],
                observations=[_obs("10.0.0.1", "GET", "/search [q parameter]")]),
    ]


def _listed():
    return Finding(title="XSS", severity="Medium", description="d", source_tool="zap",
                   hosts=[Host(ip="10.0.0.1")],
                   observations=[_obs("10.0.0.1", "GET", "/a"), _obs("10.0.0.1", "POST", "/b [q parameter]")])


class _RecordingPDF(pdf_module.FPDF):
    """Keeps the text of every multi_cell call, because PDF streams are compressed."""
    texts: list[str] = []

    def multi_cell(self, w, h=None, text="", *args, **kwargs):
        _RecordingPDF.texts.append(text)
        return super().multi_cell(w, h, text, *args, **kwargs)


def _pdf_texts(tmp_path, findings, unicode_font=True):
    _RecordingPDF.texts = []
    with patch.object(pdf_module, "FPDF", _RecordingPDF):
        if unicode_font:
            ScanfuseEngine(str(tmp_path)).export_pdf(findings)
        else:
            with patch.object(pdf_module, "_unicode_font_path", return_value=None):
                ScanfuseEngine(str(tmp_path)).export_pdf(findings)
    assert (tmp_path / "report.pdf").read_bytes().startswith(b"%PDF")
    return list(_RecordingPDF.texts)


def test_pdf_shows_host_method_and_location_after_the_hosts(tmp_path):
    texts = _pdf_texts(tmp_path, _two_findings())
    assert "Affected:\n10.0.0.1 POST /login" in texts
    assert "Affected:\n10.0.0.1 GET /search [q parameter]" in texts


def test_pdf_affected_is_also_written_with_the_core_font(tmp_path):
    texts = _pdf_texts(tmp_path, _two_findings(), unicode_font=False)
    assert "Affected:\n10.0.0.1 POST /login" in texts


def test_pdf_lists_every_place_of_one_alert(tmp_path):
    texts = _pdf_texts(tmp_path, [_listed()])
    assert "Affected:\n10.0.0.1 GET /a\n10.0.0.1 POST /b [q parameter]" in texts


def test_sarif_results_use_logical_locations_and_carry_observations(tmp_path):
    findings = _two_findings() + [_listed()]
    ScanfuseEngine(str(tmp_path)).export_sarif(findings)
    data = json.loads((tmp_path / "report.sarif").read_text(encoding="utf-8"))
    results = data["runs"][0]["results"]
    # A host is not a file: no physicalLocation and no artifactLocation anywhere.
    assert "physicalLocation" not in json.dumps(results)
    assert "artifactLocation" not in json.dumps(results)
    assert results[0]["locations"] == [{"logicalLocations": [{"name": "10.0.0.1", "kind": "resource"}]}]
    props = [r["properties"] for r in results]
    assert props[0]["hosts"] == [{"ip": "10.0.0.1"}]
    assert [(o["host"], o["method"], o["location"], o["source_tool"]) for o in props[2]["observations"]] == [
        ("10.0.0.1", "GET", "/a", "zap"), ("10.0.0.1", "POST", "/b [q parameter]", "zap")]


def test_sarif_result_without_host_has_no_locations(tmp_path):
    finding = Finding(title="T", severity="Low", description="d", source_tool="x")
    ScanfuseEngine(str(tmp_path)).export_sarif([finding])
    data = json.loads((tmp_path / "report.sarif").read_text(encoding="utf-8"))
    assert "locations" not in data["runs"][0]["results"][0]


def test_markdown_html_csv_and_json_show_host_method_and_all_places(tmp_path):
    findings = _two_findings() + [_listed()]
    engine = ScanfuseEngine(str(tmp_path))
    engine.export_findings(findings)
    first = (tmp_path / "sql-injection.md").read_text(encoding="utf-8")
    assert "**Affected**:\n\n- 10.0.0.1 POST /login" in first or "- 10.0.0.1 POST /login" in first
    listed = (tmp_path / "xss.md").read_text(encoding="utf-8")
    assert "- 10.0.0.1 GET /a" in listed and "- 10.0.0.1 POST /b \\[q parameter\\]" in listed
    index = (tmp_path / "index.md").read_text(encoding="utf-8")
    assert "at POST /login (Source" in index
    assert "at 2 locations (Source" in index
    page = (tmp_path / "report.html").read_text(encoding="utf-8")
    assert "POST /login" in page and "10.0.0.1 get /a" in page
    engine.export_csv(findings)
    with (tmp_path / "report.csv").open(newline="", encoding="utf-8") as stream:
        rows = list(csv.reader(stream))
    assert [r[-1] for r in rows[1:]] == ["10.0.0.1 POST /login", "10.0.0.1 GET /search [q parameter]",
                                         "10.0.0.1 GET /a\n10.0.0.1 POST /b [q parameter]"]
    engine.export_json(findings)
    data = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))["findings"]
    assert data[0]["observations"] == [
        {"host": "10.0.0.1", "method": "POST", "location": "/login", "source_tool": "zap"}]
    assert [o["location"] for o in data[2]["observations"]] == ["/a", "/b [q parameter]"]
    assert "location" not in data[0] and "locations" not in data[0]


def _zap_file(path, host, paths):
    items = "".join(
        f"<instance><uri>https://{host}.test{p}</uri><method>GET</method></instance>" for p in paths
    )
    path.write_text(
        f'<OWASPZAPReport><site host="{host}" port="443"><alerts><alertitem><pluginid>7</pluginid>'
        f"<name>XSS</name><riskcode>3</riskcode><desc>d</desc><instances>{items}</instances>"
        "</alertitem></alerts></site></OWASPZAPReport>",
        encoding="utf-8",
    )
    return str(path)


def test_host_filter_after_merge_leaves_nothing_of_the_other_host_in_any_format(tmp_path):
    # Same alert on two hosts, with the same locations: one finding with both hosts.
    # Another pair with different locations stays two findings and is dropped for host-b.
    a = _zap_file(tmp_path / "a.xml", "host-a", ["/shared", "/only-a-secret"])
    b = _zap_file(tmp_path / "b.xml", "host-b", ["/shared", "/only-a-secret"])
    c = tmp_path / "c.xml"
    _zap_file(c, "host-b", ["/only-b-secret", "/shared"])
    cmd = [a, b, str(c), "-f", "zap", "--host", "host-a", "--format-out"]
    out = tmp_path / "out"
    for fmt in ("markdown", "json", "csv", "pdf"):
        result = CliRunner().invoke(app, [*cmd, fmt, "-o", str(out / fmt)])
        assert result.exit_code == 0, result.stdout
    texts = {}
    for name in ("json/report.json", "csv/report.csv", "markdown/index.md", "markdown/xss.md",
                 "markdown/report.html"):
        texts[name] = (out / name).read_text(encoding="utf-8")
    pdf_texts = _pdf_texts(tmp_path / "pdfout", app_filtered(a, b, str(c), tmp_path))
    for name, text in {**texts, "pdf": "\n".join(pdf_texts)}.items():
        assert "host-b" not in text, name
        assert "only-b-secret" not in text, name
        if name != "markdown/index.md":
            assert "/only-a-secret" in text, name
    data = json.loads(texts["json/report.json"])["findings"]
    assert len(data) == 1
    assert [h["hostname"] for h in data[0]["hosts"]] == ["host-a"]
    assert {o["host"] for o in data[0]["observations"]} == {"host-a"}
    assert all("host-b" not in json.dumps(e) for e in data[0]["evidence"])
    assert len(data[0]["evidence"]) == 2


def app_filtered(a, b, c, tmp_path):
    engine = ScanfuseEngine(str(tmp_path / "x"))
    found = [f for p in (a, b, c) for f in engine.process_file(p, "zap")]
    return deduplicate_findings(engine.filter_by_host(found, "host-a"))


def test_host_filter_keeps_evidence_that_names_no_host(tmp_path):
    engine = ScanfuseEngine(str(tmp_path))
    finding = Finding(
        title="T", severity="Low", description="d", source_tool="nessus",
        hosts=[Host(ip="10.0.0.1"), Host(ip="10.0.0.2")],
        evidence=[Evidence(type="plugin-output", data="no host named")],
    )
    (kept,) = engine.filter_by_host([finding], "10.0.0.1")
    assert [h.ip for h in kept.hosts] == ["10.0.0.1"]
    assert [e.data for e in kept.evidence] == ["no host named"]


def test_merged_observations_keep_the_tool_that_reported_each(tmp_path):
    zap = Finding(title="XSS", severity="High", description="z", source_tool="zap", port="443/tcp",
                  hosts=[Host(ip="10.0.0.1")], observations=[_obs("10.0.0.1", "GET", "/a")])
    burp = Finding(title="xss", severity="High", description="b", source_tool="burp", port="443/tcp",
                   hosts=[Host(ip="10.0.0.2")], observations=[_obs("10.0.0.2", "GET", "/a", "burp")])
    merged = deduplicate_findings([zap, burp])
    ScanfuseEngine(str(tmp_path)).export_json(merged)
    (finding,) = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))["findings"]
    assert [(o["host"], o["source_tool"]) for o in finding["observations"]] == [
        ("10.0.0.1", "zap"), ("10.0.0.2", "burp")]
    assert finding["source_tool"] == "zap, burp"


def test_slugs_of_long_equal_titles_stay_within_100_characters():
    title = "Long title " * 11
    assert len(slugify(title)) == 100
    seen: set[str] = set()
    slugs = [unique_slug(title, seen) for _ in range(12)]
    assert len(set(slugs)) == 12
    assert all(len(s) <= 100 for s in slugs)
    assert slugs[1].endswith("-1") and slugs[11].endswith("-11")


def test_slug_suffix_never_produces_a_reserved_or_empty_slug():
    seen: set[str] = set()
    for _ in range(3):
        assert unique_slug("index", seen) not in RESERVED_SLUGS
    assert unique_slug("x" * 120, seen) == "x" * 100
    assert unique_slug("x" * 120, seen) == "x" * 98 + "-1"


def _nuclei_file(path, host, severity, cvss):
    path.write_text(json.dumps({
        "template-id": "t1", "host": host, "ip": host, "matched-at": f"http://{host}/x",
        "info": {"name": "Same title", "severity": severity, "classification": {"cvss-score": cvss}},
        "request": f"GET /x HTTP/1.1 for {host}",
    }) + "\n", encoding="utf-8")
    return str(path)


def test_host_filter_runs_before_merging_so_severity_comes_from_the_selected_host(tmp_path):
    a = _nuclei_file(tmp_path / "a.jsonl", "10.0.0.1", "low", 2.0)
    b = _nuclei_file(tmp_path / "b.jsonl", "10.0.0.2", "critical", 9.8)
    run = lambda *opts: CliRunner().invoke(app, [a, b, "-f", "nuclei", *opts])  # noqa: E731

    # Host A is Low, so nothing is left at High or above, in every format.
    for fmt in ("json", "csv", "markdown", "sarif"):
        out = tmp_path / f"none-{fmt}"
        result = run("--host", "10.0.0.1", "--min-severity", "High", "--format-out", fmt, "-o", str(out))
        assert result.exit_code == 0, result.stdout
        assert "No findings left" in result.stdout
        assert not out.exists() or not any(out.iterdir())

    for fmt, name in (("json", "report.json"), ("csv", "report.csv"), ("markdown", "index.md"),
                      ("sarif", "report.sarif")):
        out = tmp_path / fmt
        result = run("--host", "10.0.0.1", "--format-out", fmt, "-o", str(out))
        assert result.exit_code == 0, result.stdout
        text = "\n".join(p.read_text(encoding="utf-8") for p in sorted(out.iterdir()) if p.suffix in
                         (".json", ".csv", ".md", ".sarif"))
        assert "10.0.0.2" not in text, fmt
        assert "9.8" not in text and "| Critical | 1 |" not in text, fmt
        assert '"Critical"' not in text and ",Critical," not in text, fmt
        assert "Low" in text, fmt
    (finding,) = json.loads((tmp_path / "json" / "report.json").read_text(encoding="utf-8"))["findings"]
    assert finding["severity"] == "Low"
    assert finding["cvss_score"] == 2.0
    assert [h["ip"] for h in finding["hosts"]] == ["10.0.0.1"]
    assert {o["host"] for o in finding["observations"]} == {"10.0.0.1"}
    assert all("10.0.0.2" not in json.dumps(e) for e in finding["evidence"])
    assert "10.0.0.2" not in json.dumps(finding.get("sources", []))
