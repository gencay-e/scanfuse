import json

from typer.testing import CliRunner

from scanfuse.cli import app
from scanfuse.config import apply_overrides
from scanfuse.models import Finding, Host


def _finding() -> Finding:
    return Finding(title="Issue", severity="Low", description="desc", source_tool="scanner",
                   identifiers=["CVE-2024-1234"], hosts=[Host(ip="192.0.2.1")])


def test_override_changes_severity_and_adds_tags():
    result = apply_overrides([_finding()], {
        "overrides": [{"cve": "CVE-2024-1234", "severity": "High", "tags": ["confirmed"]}],
    })
    assert result[0].severity == "High"
    assert result[0].tags == ["confirmed"]


def test_exclusion_removes_matching_host():
    assert apply_overrides([_finding()], {"exclusions": [{"host": "192.0.2.*"}]}) == []


def test_severity_override_is_applied_before_minimum_filter(tmp_path, monkeypatch):
    (tmp_path / ".scanfuse.yaml").write_text(
        "overrides:\n  - cve: CVE-2024-1234\n    severity: High\n",
        encoding="utf-8",
    )
    source = tmp_path / "input.json"
    source.write_text(json.dumps({
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "test"}}, "results": [{
            "ruleId": "CVE-2024-1234", "level": "note",
            "message": {"text": "Issue"},
        }]}],
    }), encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(app, [str(source), "--format", "sarif",
                                      "--format-out", "json", "--min-severity", "High",
                                      "-o", str(tmp_path / "out")])
    assert result.exit_code == 0, result.stdout
    assert len(json.loads((tmp_path / "out" / "report.json").read_text())["findings"]) == 1
