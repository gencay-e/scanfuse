import json
from pathlib import Path

import pytest
from pypdf import PdfReader
from typer.testing import CliRunner

from scanfuse.baseline import compare_baseline
from scanfuse.cli import app
from scanfuse.engine import ScanfuseEngine
from scanfuse.models import Finding, Host, Observation


def item(title="Rule", host="192.0.2.1", location="/a"):
    return Finding(title=title, severity="High", description="Description", source_tool="test",
                   hosts=[Host(ip=host)], observations=[Observation(host=host, location=location, source_tool="test")])


def baseline(tmp_path, findings):
    path = tmp_path / "baseline"
    ScanfuseEngine(str(path)).export_json(findings)
    return path / "report.json"


def test_comparison_uses_merge_identity_and_preserves_partial_hosts(tmp_path):
    path = baseline(tmp_path, [item(), item("Gone")])
    current = [item(host="192.0.2.2"), item("Added"), item(location="/b")]
    resolved = compare_baseline(current, path)
    assert [f.status for f in current] == ["unchanged", "new", "new"]
    assert [(f.title, f.status) for f in resolved] == [("Gone", "resolved")]


@pytest.mark.parametrize("kind", ["json", "csv", "markdown", "pdf"])
def test_status_exports(tmp_path, kind):
    path = baseline(tmp_path, [item(), item("Gone")])
    current = [item(), item("Added")]
    engine = ScanfuseEngine(str(tmp_path / kind))
    engine.resolved = compare_baseline(current, path)
    getattr(engine, "export_findings" if kind == "markdown" else "export_" + kind)(current)
    if kind == "json":
        data = json.loads((engine.output_dir / "report.json").read_text())
        assert [f["status"] for f in data["findings"]] == ["unchanged", "new"]
        assert data["resolved"][0]["title"] == "Gone"
    elif kind == "markdown":
        for name in ["index.md", "report.html"]:
            text = (engine.output_dir / name).read_text(encoding="utf-8")
            assert "resolved" in text and "Gone" in text and "unchanged" in text
    elif kind == "csv":
        text = (engine.output_dir / "report.csv").read_text()
        assert "Retest Status" in text and "unchanged" in text and "new" in text
    else:
        text = "\n".join(page.extract_text() for page in PdfReader(engine.output_dir / "report.pdf").pages)
        assert "unchanged" in text and "new" in text
        assert "Resolved findings: 1" in text and "Gone" in text


def test_cli_empty_retest_exports_resolved(tmp_path):
    path = baseline(tmp_path, [item()])
    source = tmp_path / "empty.json"
    source.write_text('{"matches": []}')
    out = tmp_path / "out"
    result = CliRunner().invoke(app, [str(source), "-f", "grype", "--baseline", str(path), "--format-out", "json", "-o", str(out)])
    assert result.exit_code == 0, result.output
    data = json.loads((out / "report.json").read_text())
    assert data["findings"] == []
    assert data["resolved"][0]["status"] == "resolved"


def test_incomplete_baseline_rejected(tmp_path):
    path = baseline(tmp_path, [item()])
    data = json.loads(path.read_text())
    data["complete"] = False
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="complete"):
        compare_baseline([], path)


def test_incomplete_current_scan_never_claims_resolution(tmp_path):
    path = baseline(tmp_path, [item()])
    source = tmp_path / "broken.json"
    source.write_text("{not json", encoding="utf-8")
    out = tmp_path / "out"
    result = CliRunner().invoke(app, [str(source), "--baseline", str(path), "--format-out", "json", "-o", str(out)])
    assert result.exit_code == 1, result.output
    data = json.loads((out / "report.json").read_text())
    assert data["complete"] is False
    assert data["resolved"] == []


def test_invalid_config_with_empty_input_exports_incomplete_report(tmp_path):
    source = tmp_path / "empty.json"
    source.write_text('{"matches": []}', encoding="utf-8")
    config = tmp_path / "config.yaml"
    config.write_text("overrides:\n  - title: admin\n    severity: [High]\n", encoding="utf-8")
    out = tmp_path / "out"
    result = CliRunner().invoke(app, [str(source), "-f", "grype", "-c", str(config), "--format-out", "json", "-o", str(out)])
    assert result.exit_code == 1, result.output
    data = json.loads((out / "report.json").read_text())
    assert data["complete"] is False
    assert "severity" in data["errors"][0]["message"]


@pytest.mark.parametrize("restriction", ["host", "severity", "exclusion", "ignore", "override"])
def test_resolved_findings_respect_current_report_filters(tmp_path, restriction):
    source = tmp_path / "scan.json"
    source.write_text(json.dumps([
        {"id": "TLS-A", "ip": "192.0.2.1", "port": "443", "severity": "HIGH", "finding": "A"},
        {"id": "TLS-B", "ip": "192.0.2.2", "port": "443", "severity": "LOW", "finding": "B"},
    ]), encoding="utf-8")
    runner = CliRunner()
    initial = tmp_path / "initial"
    args = [str(source), "--format-out", "json"]
    assert runner.invoke(app, [*args, "-o", str(initial)]).exit_code == 0
    options = []
    if restriction == "host":
        options = ["--host", "192.0.2.1"]
    elif restriction == "severity":
        options = ["--min-severity", "High"]
    else:
        config = tmp_path / "rules.yaml"
        text = {
            "exclusion": "exclusions:\n  - title: TLS-B\n",
            "ignore": "ignore_titles: [TLS-B]\n",
            "override": "overrides:\n  - title: TLS-B\n    severity: Info\n",
        }[restriction]
        config.write_text(text, encoding="utf-8")
        options = ["--config", str(config), "--min-severity", "Low"]
    out = tmp_path / "retest"
    result = runner.invoke(app, [*args, "--baseline", str(initial / "report.json"), *options, "-o", str(out)])
    assert result.exit_code == 0, result.output
    report = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert len(report["findings"]) == 1
    assert report["findings"][0]["status"] == "unchanged"
    assert report["resolved"] == []


def test_baseline_identity_includes_prefix_value_tool_ids(tmp_path):
    previous = item()
    previous.identifiers = ["scanner-rule:one"]
    path = baseline(tmp_path, [previous])
    current = item()
    current.identifiers = ["scanner-rule:two"]
    resolved = compare_baseline([current], path)
    assert current.status == "new"
    assert [(f.identifiers, f.status) for f in resolved] == [(["scanner-rule:one"], "resolved")]


def test_baseline_tolerates_added_and_removed_secondary_scanners(tmp_path):
    nessus = Finding(
        title="SQL Injection", severity="High", description="Desc", source_tool="nessus",
        identifiers=["nessus-plugin:1"], hosts=[Host(ip="192.0.2.1")],
        observations=[Observation(host="192.0.2.1", location="/login", source_tool="nessus")],
    )
    merged = Finding(
        title="SQL Injection", severity="High", description="Desc", source_tool="nessus, zap",
        identifiers=["nessus-plugin:1", "zap-plugin:2"], hosts=[Host(ip="192.0.2.1")],
        observations=[
            Observation(host="192.0.2.1", location="/login", source_tool="nessus"),
            Observation(host="192.0.2.1", location="/login", source_tool="zap"),
        ],
    )
    resolved_added = compare_baseline([merged], baseline(tmp_path / "b1", [nessus]))
    assert merged.status == "unchanged"
    assert resolved_added == []

    nessus_copy = nessus.model_copy(deep=True)
    resolved_removed = compare_baseline([nessus_copy], baseline(tmp_path / "b2", [merged]))
    assert nessus_copy.status == "unchanged"
    assert resolved_removed == []


def test_cli_compares_active_downgraded_finding_before_min_severity(tmp_path, monkeypatch):
    source = tmp_path / "scan.json"
    source.write_text(json.dumps([{
        "id": "TLS-A", "ip": "192.0.2.1", "port": "443", "severity": "HIGH", "finding": "A"
    }]), encoding="utf-8")
    initial = tmp_path / "initial"
    assert CliRunner().invoke(app, [str(source), "--format-out", "json", "-o", str(initial)]).exit_code == 0
    config = tmp_path / "rules.yaml"
    config.write_text("overrides:\n  - title: A\n    severity: Low\n", encoding="utf-8")
    observed = []
    original = compare_baseline

    def capture(findings, path, **kwargs):
        observed.extend(findings)
        return original(findings, path, **kwargs)

    monkeypatch.setattr("scanfuse.cli.compare_baseline", capture)
    result = CliRunner().invoke(app, [str(source), "--baseline", str(initial / "report.json"),
                                      "--config", str(config), "--min-severity", "High",
                                      "--format-out", "json", "-o", str(tmp_path / "retest")])
    assert result.exit_code == 0, result.output
    assert len(observed) == 1 and observed[0].severity == "Low"
    data = json.loads((tmp_path / "retest" / "report.json").read_text(encoding="utf-8"))
    assert data["resolved"] == []


def test_stdin_temp_file_is_removed_and_fd_closed_when_write_fails(tmp_path, monkeypatch):
    import os
    import sys

    import scanfuse.cli as cli

    created = {}
    real_mkstemp = cli.tempfile.mkstemp

    def capture_mkstemp(*args, **kwargs):
        fd, name = real_mkstemp(*args, dir=tmp_path, **kwargs)
        created.update(fd=fd, name=name)
        return fd, name

    class BrokenStdin:
        buffer = object()

        def isatty(self):
            return False

    def fail_fdopen(*args, **kwargs):
        raise OSError("open failed")

    monkeypatch.setattr(cli.tempfile, "mkstemp", capture_mkstemp)
    monkeypatch.setattr(cli.os, "fdopen", fail_fdopen)
    monkeypatch.setattr(sys, "stdin", BrokenStdin())
    result = CliRunner().invoke(app, ["-"])
    assert isinstance(result.exception, OSError)
    assert not Path(created["name"]).exists()
    with pytest.raises(OSError):
        os.fstat(created["fd"])


def test_baseline_empty_local_ids_do_not_match_populated_same_tool_ids(tmp_path):
    first = Finding(title="Same Rule", severity="High", description="D", source_tool="nessus", identifiers=["nessus-plugin:1"])
    second = Finding(title="Same Rule", severity="High", description="D", source_tool="nessus", identifiers=["nessus-plugin:2"])
    current = Finding(title="Same Rule", severity="High", description="D", source_tool="nessus", identifiers=[])
    resolved = compare_baseline([current], baseline(tmp_path, [first, second]))
    assert current.status == "new"
    assert len(resolved) == 2 and all(f.status == "resolved" for f in resolved)


def test_cli_excludes_other_hosts_from_baseline_matching(tmp_path):
    previous = baseline(tmp_path, [item(host="192.0.2.2")])
    source = tmp_path / "source"
    ScanfuseEngine(str(source)).export_sarif([item(host="192.0.2.1")])
    output = tmp_path / "retest"
    result = CliRunner().invoke(app, [str(source / "report.sarif"), "--baseline", str(previous),
                                      "--host", "192.0.2.1", "--format-out", "json", "-o", str(output)])
    assert result.exit_code == 0, result.output
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    assert [f["status"] for f in report["findings"]] == ["new"]
    assert report["resolved"] == []


def _raise_recursion_error(*_args, **_kwargs):
    raise RecursionError("maximum recursion depth exceeded")


@pytest.mark.parametrize("malformation,message", [
    ("surrogate", "invalid Unicode surrogates"),
    ("deep_list", "INCOMPLETE"),
    ("nesting", "JSON nesting is too deep"),
])
def test_cli_malformed_baseline_exports_incomplete_report(tmp_path, monkeypatch, malformation, message):
    previous = tmp_path / "baseline.json"
    if malformation == "surrogate":
        previous.write_text(json.dumps({
            "schema_version": 2, "complete": True, "findings": [item("Gone\ud800").model_dump()],
        }), encoding="utf-8")
    elif malformation == "deep_list":
        previous.write_text("[" * 5000 + "]" * 5000, encoding="utf-8")
    else:
        previous.write_text("{}", encoding="utf-8")
        monkeypatch.setattr("scanfuse.baseline.json.loads", _raise_recursion_error)
    source = tmp_path / "scan.json"
    source.write_text('{"matches": []}', encoding="utf-8")
    out = tmp_path / "out"

    result = CliRunner().invoke(app, [str(source), "-f", "grype", "--baseline", str(previous), "-o", str(out)])
    assert result.exit_code == 1, result.output
    index = (out / "index.md").read_text(encoding="utf-8")
    assert "INCOMPLETE" in index
    assert message in index


def test_cli_deep_config_exports_incomplete_report(tmp_path):
    config = tmp_path / "config.yaml"
    config.write_text("overrides: " + "[" * 500 + "]" * 500, encoding="utf-8")
    source = tmp_path / "scan.json"
    source.write_text('{"matches": []}', encoding="utf-8")
    out = tmp_path / "out"
    result = CliRunner().invoke(app, [str(source), "-f", "grype", "-c", str(config),
                                    "--format-out", "json", "-o", str(out)])
    assert result.exit_code == 1, result.output
    report = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert report["complete"] is False
    assert "YAML nesting is too deep" in report["errors"][0]["message"]
