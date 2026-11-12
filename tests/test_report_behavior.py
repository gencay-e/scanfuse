"""Behavior of the report output: overwrite protection, incomplete runs, option checks, escaping."""
import csv
import hashlib
import json
import os

import pytest
from typer.testing import CliRunner

from scanfuse import __version__
from scanfuse.cli import app
from scanfuse.engine import ScanfuseEngine
from scanfuse.models import Evidence, Finding, Host, Observation

runner = CliRunner(env={"COLUMNS": "400"})
FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def nuclei_file(path, names, host="10.0.0.1"):
    path.write_text(
        "\n".join(json.dumps({"template-id": f"t{i}", "host": host, "info": {"name": n, "severity": "high"}})
                  for i, n in enumerate(names)),
        encoding="utf-8",
    )
    return str(path)


def digest(directory):
    return {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(directory.iterdir())
            if p.is_file()}


@pytest.fixture(autouse=True)
def in_tmp(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)


# ------------------------------------------------------------ overwrite protection

def test_second_run_without_replace_stops_and_leaves_files_unchanged(tmp_path):
    source = nuclei_file(tmp_path / "a.json", ["Alpha", "Beta"])
    first = runner.invoke(app, [source, "-o", "out"])
    assert first.exit_code == 0, first.stdout
    before = digest(tmp_path / "out")
    other = nuclei_file(tmp_path / "b.json", ["Gamma"])
    second = runner.invoke(app, [other, "-o", "out"])
    assert second.exit_code == 2
    assert "--replace" in second.stdout
    assert digest(tmp_path / "out") == before


@pytest.mark.parametrize("fmt, name", [("json", "report.json"), ("csv", "report.csv")])
def test_json_and_csv_are_not_overwritten_either(tmp_path, fmt, name):
    source = nuclei_file(tmp_path / "a.json", ["Alpha"])
    assert runner.invoke(app, [source, "-o", "out", "--format-out", fmt]).exit_code == 0
    before = (tmp_path / "out" / name).read_bytes()
    result = runner.invoke(app, [nuclei_file(tmp_path / "b.json", ["Other"]), "-o", "out",
                                 "--format-out", fmt])
    assert result.exit_code == 2
    assert (tmp_path / "out" / name).read_bytes() == before


def test_replace_overwrites_and_removes_files_of_the_old_report_only(tmp_path):
    first = nuclei_file(tmp_path / "a.json", ["Alpha", "Beta"])
    assert runner.invoke(app, [first, "-o", "out"]).exit_code == 0
    (tmp_path / "out" / "notes.txt").write_text("mine", encoding="utf-8")
    assert (tmp_path / "out" / "beta.md").exists()
    second = nuclei_file(tmp_path / "b.json", ["Alpha"])
    result = runner.invoke(app, [second, "-o", "out", "--replace"])
    assert result.exit_code == 0, result.stdout
    assert not (tmp_path / "out" / "beta.md").exists()
    assert (tmp_path / "out" / "alpha.md").exists()
    assert (tmp_path / "out" / "notes.txt").read_text(encoding="utf-8") == "mine"
    assert "Total Findings: 1" in (tmp_path / "out" / "index.md").read_text(encoding="utf-8")


def test_failed_export_keeps_the_old_report_complete(tmp_path, monkeypatch):
    out = tmp_path / "out"
    engine = ScanfuseEngine(str(out))
    old = [Finding(title="Old", severity="High", description="old", source_tool="t")]
    engine.export_findings(old)
    before = digest(out)

    def boom(*_args, **_kwargs):
        raise RuntimeError("render failed")

    monkeypatch.setattr(ScanfuseEngine, "_render_html", staticmethod(boom))
    new = [Finding(title="New", severity="Low", description="new", source_tool="t")]
    with pytest.raises(RuntimeError):
        engine.export_findings(new, replace=True)
    assert digest(out) == before
    assert not [p for p in out.iterdir() if p.name.startswith(".scanfuse-staging-")]


def test_failed_publish_restores_previous_report(tmp_path, monkeypatch):
    out = tmp_path / "out"
    engine = ScanfuseEngine(str(out))
    engine.export_findings([Finding(title="Alpha", severity="High", description="old", source_tool="t")])
    before = digest(out)
    original_replace = os.replace
    calls = 0

    def fail_second_publish(src, dst):
        nonlocal calls
        if os.path.basename(os.path.dirname(src)).startswith(".scanfuse-staging-"):
            calls += 1
            if calls == 2:
                raise OSError("publish failed")
        return original_replace(src, dst)

    monkeypatch.setattr(os, "replace", fail_second_publish)
    with pytest.raises(OSError, match="publish failed"):
        engine.export_findings([Finding(title="Alpha", severity="Low", description="new", source_tool="t")], replace=True)
    assert digest(out) == before


def test_failed_stale_removal_restores_previous_report(tmp_path, monkeypatch):
    out = tmp_path / "out"
    engine = ScanfuseEngine(str(out))
    engine.export_findings([Finding(title="Old", severity="High", description="old", source_tool="t")])
    before = digest(out)
    from pathlib import Path
    original_unlink = Path.unlink

    def fail_stale(path, *args, **kwargs):
        if path == out / "old.md":
            raise OSError("cleanup failed")
        return original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", fail_stale)
    with pytest.raises(OSError, match="cleanup failed"):
        engine.export_findings([Finding(title="New", severity="Low", description="new", source_tool="t")], replace=True)
    assert digest(out) == before


def test_output_path_that_is_a_file_is_rejected_and_untouched(tmp_path):
    target = tmp_path / "out"
    target.write_text("keep", encoding="utf-8")
    result = runner.invoke(app, [nuclei_file(tmp_path / "a.json", ["A"]), "-o", "out"])
    assert result.exit_code == 2
    assert "Traceback" not in result.stdout
    assert target.read_text(encoding="utf-8") == "keep"


# ------------------------------------------------------------- incomplete runs

def test_nuclei_broken_jsonl_keeps_valid_findings_and_marks_incomplete(tmp_path):
    source = tmp_path / "mixed.jsonl"
    source.write_text(json.dumps({"template-id": "t", "info": {"name": "Valid", "severity": "high"}})
                      + "\n{broken json\n", encoding="utf-8")
    result = runner.invoke(app, [str(source), "-o", "out", "--format-out", "json"])
    assert result.exit_code == 1
    report = json.loads((tmp_path / "out" / "report.json").read_text(encoding="utf-8"))
    assert report["complete"] is False
    assert [finding["title"] for finding in report["findings"]] == ["Valid"]
    assert "line 2" in report["errors"][0]["message"]


def test_nuclei_broken_array_keeps_valid_findings_and_marks_incomplete(tmp_path):
    source = tmp_path / "mixed.json"
    source.write_text(json.dumps([
        {"template-id": "t", "info": {"name": "Valid"}},
        {"template-id": "bad", "host": {"unexpected": "object"}},
    ]), encoding="utf-8")
    result = runner.invoke(app, [str(source), "-o", "out", "--format", "nuclei", "--format-out", "json"])
    assert result.exit_code == 1
    report = json.loads((tmp_path / "out" / "report.json").read_text(encoding="utf-8"))
    assert report["complete"] is False
    assert [finding["title"] for finding in report["findings"]] == ["Valid"]
    assert "array position 2" in report["errors"][0]["message"]


def test_partial_failure_is_marked_in_every_format(tmp_path):
    good = nuclei_file(tmp_path / "good.json", ["Alpha"])
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    for fmt in ("json", "csv", "markdown"):
        result = runner.invoke(app, [good, str(bad), "-o", f"out-{fmt}", "--format-out", fmt])
        assert result.exit_code == 1, (fmt, result.stdout)

    data = json.loads((tmp_path / "out-json" / "report.json").read_text(encoding="utf-8"))
    assert data["schema_version"] == 2
    assert data["complete"] is False
    assert [e["file"] for e in data["errors"]] == [str(bad)]
    assert [f["title"] for f in data["findings"]] == ["Alpha"]

    with (tmp_path / "out-csv" / "report.csv").open(newline="", encoding="utf-8") as stream:
        rows = list(csv.reader(stream))
    assert rows[0][-2:] == ["Import Status", "Affected"]
    assert rows[1][-2].startswith("incomplete")

    index = (tmp_path / "out-markdown" / "index.md").read_text(encoding="utf-8")
    assert "INCOMPLETE" in index
    assert "INCOMPLETE" in (tmp_path / "out-markdown" / "report.html").read_text(encoding="utf-8")


def test_complete_run_is_marked_complete(tmp_path):
    good = nuclei_file(tmp_path / "good.json", ["Alpha"])
    assert runner.invoke(app, [good, "-o", "out", "--format-out", "json"]).exit_code == 0
    data = json.loads((tmp_path / "out" / "report.json").read_text(encoding="utf-8"))
    assert (data["complete"], data["errors"]) == (True, [])


def test_only_bad_input_exports_nothing_and_exits_1(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    result = runner.invoke(app, [str(bad), "-o", "out"])
    assert result.exit_code == 1
    assert not (tmp_path / "out").exists()


# ---------------------------------------------------------------- option checks

@pytest.mark.parametrize("args", [
    ["--min-severity", "Banana"],
    ["--format-out", "xyz"],
    ["-f", "foo"],
    ["-t", "/does/not/exist"],
])
def test_invalid_option_values_are_rejected_with_exit_2(tmp_path, args):
    source = nuclei_file(tmp_path / "a.json", ["A"])
    result = runner.invoke(app, [source, "-o", "out", *args])
    assert result.exit_code == 2
    assert not (tmp_path / "out").exists()


def test_severity_and_format_names_ignore_case(tmp_path):
    source = nuclei_file(tmp_path / "a.json", ["A"])
    result = runner.invoke(app, [source, "-o", "out", "-s", "hIgH", "-f", "NUCLEI",
                                 "--format-out", "JSON"])
    assert result.exit_code == 0, result.stdout


def test_host_filter_is_exact_with_optional_wildcards(tmp_path):
    findings = [
        Finding(title="One", severity="High", description="d", source_tool="t",
                hosts=[Host(ip="10.0.0.1", hostname="Web.Example.test")]),
        Finding(title="Ten", severity="High", description="d", source_tool="t",
                hosts=[Host(ip="10.0.0.10")]),
        Finding(title="Far", severity="High", description="d", source_tool="t",
                hosts=[Host(ip="110.0.0.1")]),
    ]
    engine = ScanfuseEngine(str(tmp_path / "x"))
    titles = lambda **kw: [f.title for f in engine.filter_by_host(findings, **kw)]  # noqa: E731
    assert titles(host_filter="10.0.0.1") == ["One"]
    assert titles(host_filter="web.example.TEST") == ["One"]
    assert titles(host_filter="10.0.0.*") == ["One", "Ten"]
    assert titles(host_filter="10.0.0") == []


def test_version_flag():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert result.stdout.strip() == f"scanfuse {__version__}"


# -------------------------------------------------------------- error messages

def test_missing_file_and_directory_are_reported_as_such(tmp_path):
    missing = runner.invoke(app, [str(tmp_path / "nope.json"), "-o", "out"])
    assert missing.exit_code == 1
    assert "File not found" in missing.stdout
    assert "auto-detect" not in missing.stdout
    directory = runner.invoke(app, [str(tmp_path), "-o", "out"])
    assert directory.exit_code == 1
    assert "directory" in directory.stdout


def test_explicit_wrong_format_is_an_error_not_a_bogus_finding(tmp_path):
    result = runner.invoke(app, [os.path.join(FIXTURES, "dummy_trivy.json"), "-f", "nuclei",
                                 "-o", "out"])
    assert result.exit_code == 1
    assert "Not a valid Nuclei" in result.stdout
    assert not (tmp_path / "out").exists()


def test_xml_entities_are_rejected_with_a_readable_message(tmp_path):
    source = tmp_path / "evil.xml"
    source.write_text(
        '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/hostname">]>'
        "<nmaprun>&x;</nmaprun>", encoding="utf-8")
    result = runner.invoke(app, [str(source), "-f", "nmap", "-o", "out"])
    assert result.exit_code == 1
    assert "entity" in result.stdout
    assert "EntitiesForbidden(" not in result.stdout


def test_yaml_syntax_error_in_config_is_an_error(tmp_path):
    (tmp_path / ".scanfuse.yaml").write_text("ignore_titles: [\n", encoding="utf-8")
    source = nuclei_file(tmp_path / "a.json", ["Alpha", "Ignored one"])
    result = runner.invoke(app, [source, "-o", "out", "--format-out", "json"])
    assert result.exit_code == 1
    assert ".scanfuse.yaml" in result.stdout
    data = json.loads((tmp_path / "out" / "report.json").read_text(encoding="utf-8"))
    assert data["complete"] is False
    assert len(data["findings"]) == 2


def test_stdin_errors_do_not_show_the_temp_file_name():
    result = runner.invoke(app, ["-", "-f", "nuclei", "-o", "out"], input="{not json\n")
    assert result.exit_code == 1
    assert "stdin" in result.stdout
    assert ".tmp" not in result.stdout


def test_brackets_in_messages_do_not_break_the_output(tmp_path):
    # A file name that looks like Rich markup must be printed as it is. No '/' in the name, so
    # that it is a valid file name on Windows too.
    result = runner.invoke(app, [str(tmp_path / "a[red]b[bold].json"), "-o", "out"])
    assert result.exit_code == 1
    assert "a[red]b[bold].json" in result.stdout


# ---------------------------------------------------------------- file names

def test_reserved_names_do_not_overwrite_index_or_report(tmp_path):
    titles = ["Index", "Report", "CON", "nul", "COM1", "Normal"]
    findings = [Finding(title=t, severity="Low", description=f"about {t}", source_tool="t")
                for t in titles]
    ScanfuseEngine(str(tmp_path / "out")).export_findings(findings)
    out = tmp_path / "out"
    assert "Pentest Report Summary" in (out / "index.md").read_text(encoding="utf-8")
    names = sorted(p.name for p in out.glob("*.md"))
    assert len(names) == len(titles) + 1  # one file per finding plus index.md
    for stem in ("con", "nul", "com1"):
        assert stem + ".md" not in names
    contents = " ".join((out / n).read_text(encoding="utf-8") for n in names if n != "index.md")
    for t in titles:
        assert f"about {t}" in contents


# ------------------------------------------------------- escaping and evidence

def test_evidence_is_written_unchanged_inside_a_long_enough_fence(tmp_path):
    data = "</pre><script>alert(1)</script>\n```\nrm -rf /\n````"
    finding = Finding(title="E", severity="Low", description="d", source_tool="t",
                      evidence=[Evidence(type="http-request", data=data)])
    ScanfuseEngine(str(tmp_path / "out")).export_findings([finding])
    text = (tmp_path / "out" / "e.md").read_text(encoding="utf-8")
    assert f"\n`````\n{data}\n`````\n" in text
    assert "&lt;" not in text
    assert "'''" not in text


def test_title_cannot_inject_links_or_headings_into_the_index(tmp_path):
    title = "x](https://evil.example/login) [y"
    finding = Finding(title=title, severity="High", description="## Remediation\nreal text",
                      source_tool="t", hosts=[Host(ip="1.1.1.1", hostname="a](https://evil2.example)")])
    ScanfuseEngine(str(tmp_path / "out")).export_findings([finding])
    html_text = (tmp_path / "out" / "report.html").read_text(encoding="utf-8")
    assert 'href="https://evil.example' not in html_text
    assert 'href="https://evil2.example' not in html_text
    assert "<h2>Remediation</h2>" not in html_text
    assert "real text" in html_text


def test_index_lists_findings_by_severity_not_alphabetically(tmp_path):
    findings = [Finding(title=t, severity=s, description="d", source_tool="t")
                for t, s in [("A info", "Info"), ("B low", "Low"), ("C crit", "Critical"),
                             ("D high", "High"), ("E med", "Medium")]]
    ScanfuseEngine(str(tmp_path / "out")).export_findings(findings)
    index = (tmp_path / "out" / "index.md").read_text(encoding="utf-8")
    order = [index.index(t) for t in ("C crit", "D high", "E med", "B low", "A info")]
    assert order == sorted(order)


# ----------------------------------------------------------------------- csv

@pytest.mark.parametrize("prefix", [" =", "＝", " +", " @", "＋", "＠"])
def test_csv_neutralizes_unicode_lookalike_formula_prefixes(tmp_path, prefix):
    payload = prefix + "1+1"
    finding = Finding(title=payload, severity="Low", description=payload, source_tool="t")
    ScanfuseEngine(str(tmp_path)).export_csv([finding])
    with (tmp_path / "report.csv").open(newline="", encoding="utf-8") as stream:
        rows = list(csv.reader(stream))
    assert rows[1][0] == "'" + payload
    assert rows[1][5] == "'" + payload


def test_csv_excel_option_writes_bom_and_semicolons(tmp_path):
    finding = Finding(title="Größe", severity="Low", description="d", source_tool="t")
    ScanfuseEngine(str(tmp_path)).export_csv([finding], excel=True)
    raw = (tmp_path / "report.csv").read_bytes()
    assert raw.startswith(b"\xef\xbb\xbf")
    assert raw.decode("utf-8-sig").splitlines()[0].startswith("Title;Severity;CVSS;")


def test_csv_keeps_the_first_eight_columns_of_version_0_1(tmp_path):
    ScanfuseEngine(str(tmp_path)).export_csv(
        [Finding(title="T", severity="Low", description="d", source_tool="t")])
    header = next(csv.reader((tmp_path / "report.csv").open(encoding="utf-8")))
    assert header[:8] == ["Title", "Severity", "CVSS", "Hosts", "Source Tool", "Description",
                          "Remediation", "Evidence"]


# ------------------------------------------------------ merged findings in exports

def test_exports_show_what_each_tool_reported(tmp_path):
    result = runner.invoke(app, [os.path.join(FIXTURES, "dummy_zap.xml"),
                                 os.path.join(FIXTURES, "dummy_burp_view.xml"), "-o", "out"])
    assert result.exit_code == 0, result.stdout
    text = (tmp_path / "out" / "sql-injection.md").read_text(encoding="utf-8")
    assert "## Reported by" in text
    assert "Use prepared statements." in text
    jsn = runner.invoke(app, [os.path.join(FIXTURES, "dummy_zap.xml"),
                              os.path.join(FIXTURES, "dummy_burp_view.xml"), "-o", "outj",
                              "--format-out", "json"])
    assert jsn.exit_code == 0
    findings = json.loads((tmp_path / "outj" / "report.json").read_text(encoding="utf-8"))["findings"]
    merged = next(f for f in findings if f["title"].lower() == "sql injection")
    assert {s["source_tool"] for s in merged["sources"]} == {"zap", "burp"}
    assert "zap-plugin:40018" in merged["identifiers"]


def test_indented_scanner_text_does_not_become_a_code_block(tmp_path):
    description = "First paragraph.\n\n    Indented by four spaces, as some scanners write it.\n\t\tIndented by tabs."
    finding = Finding(title="Indented", severity="Low", description=description, source_tool="t",
                      remediation="Do this.\n\n        And that.")
    ScanfuseEngine(str(tmp_path / "out")).export_findings([finding])
    html_text = (tmp_path / "out" / "report.html").read_text(encoding="utf-8")
    assert "<pre>" not in html_text.replace("<pre><code>No evidence", "")
    assert "Indented by four spaces" in html_text and "And that." in html_text


def test_a_list_in_scanner_text_stays_a_list(tmp_path):
    description = "Attacks are effective when:\n* the victim has a session\n* the victim is on the same network\nEnd."
    finding = Finding(title="List", severity="Low", description=description, source_tool="t")
    ScanfuseEngine(str(tmp_path / "out")).export_findings([finding])
    html_text = (tmp_path / "out" / "report.html").read_text(encoding="utf-8")
    assert html_text.count("<li>the victim") == 2


def test_replace_keeps_a_file_that_a_tampered_manifest_names(tmp_path):
    out = tmp_path / "out"
    engine = ScanfuseEngine(str(out))
    findings = [Finding(title="One", severity="High", description="d", source_tool="t")]
    engine.export_json(findings)
    (out / "important.txt").write_text("keep me", encoding="utf-8")
    manifest = out / ".scanfuse-manifest-json.json"
    data = json.loads(manifest.read_text(encoding="utf-8"))
    assert set(data["sha256"]) == set(data["files"])
    data["files"].append("important.txt")
    manifest.write_text(json.dumps(data), encoding="utf-8")
    engine.export_json(findings, replace=True)
    assert (out / "important.txt").read_text(encoding="utf-8") == "keep me"


def test_replace_keeps_a_stale_file_changed_after_the_export(tmp_path):
    out = tmp_path / "out"
    engine = ScanfuseEngine(str(out))
    engine.export_findings([Finding(title="One", severity="High", description="d", source_tool="t")])
    engine.export_findings([Finding(title="Two", severity="High", description="d", source_tool="t")],
                           replace=True)
    assert not (out / "one.md").exists(), "unchanged stale file is removed"
    (out / "two.md").write_text("edited by hand", encoding="utf-8")
    engine.export_findings([Finding(title="Three", severity="High", description="d", source_tool="t")],
                           replace=True)
    assert (out / "two.md").read_text(encoding="utf-8") == "edited by hand"
    assert not (out / "one.md").exists()


def test_replace_does_not_delete_files_of_an_old_manifest_without_digests(tmp_path):
    out = tmp_path / "out"
    engine = ScanfuseEngine(str(out))
    engine.export_findings([Finding(title="One", severity="High", description="d", source_tool="t")])
    manifest = out / ".scanfuse-manifest-markdown.json"
    data = json.loads(manifest.read_text(encoding="utf-8"))
    manifest.write_text(json.dumps({"files": data["files"]}), encoding="utf-8")
    engine.export_findings([Finding(title="Two", severity="High", description="d", source_tool="t")],
                           replace=True)
    assert (out / "one.md").exists()


def test_location_is_in_index_html_search_and_csv(tmp_path):
    findings = [
        Finding(title="CSRF", severity="Medium", description="d", source_tool="zap",
                observations=[Observation(host="10.0.0.1", location="/demo/a_b.php", source_tool="zap")]),
        Finding(title="CSRF", severity="Medium", description="d", source_tool="zap",
                observations=[Observation(host="10.0.0.1", location="/other.php", source_tool="zap")]),
        Finding(title="No place", severity="Low", description="d", source_tool="zap"),
    ]
    engine = ScanfuseEngine(str(tmp_path / "out"))
    engine.export_findings(findings)
    index = (tmp_path / "out" / "index.md").read_text(encoding="utf-8")
    assert "(csrf.md) at /demo/a\\_b.php (Source" in index
    assert "(no-place.md) (Source" in index
    page = (tmp_path / "out" / "report.html").read_text(encoding="utf-8")
    assert 'data-title="csrf 10.0.0.1 /other.php"' in page
    assert "Search by title or location..." in page
    engine.export_csv(findings, excel=True)
    with (tmp_path / "out" / "report.csv").open(newline="", encoding="utf-8-sig") as stream:
        rows = list(csv.reader(stream, delimiter=";"))
    assert rows[0][-1] == "Affected"
    assert [r[-1] for r in rows[1:]] == ["10.0.0.1 /demo/a_b.php", "10.0.0.1 /other.php", ""]
