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


def test_extended_match_fields_are_case_insensitive_with_substrings_and_wildcards():
    finding = _finding()
    finding.title = "Exposed ADMIN endpoint"
    finding.observations = [__import__("scanfuse.models", fromlist=["Observation"]).Observation(
        host="192.0.2.1", method="GET", location="/Admin/Users", source_tool="scanner"
    )]
    assert apply_overrides([finding], {"overrides": [{
        "source_tool": "SCAN*", "title": "admin", "location": "/Admin/*", "severity": "High"
    }]})[0].severity == "High"


def test_unknown_keys_and_invalid_severity_are_rejected():
    import pytest

    from scanfuse.config import validate_config

    with pytest.raises(ValueError, match="unknown key"):
        validate_config({"overrides": [{"titel": "typo"}]})
    with pytest.raises(ValueError, match="severity"):
        validate_config({"overrides": [{"title": "admin", "severity": "urgent"}]})



def test_config_rejects_container_severity_and_duplicate_keys(tmp_path):
    import pytest

    from scanfuse.config import load_config, validate_config

    for severity in (["High"], {"value": "High"}, None, True):
        with pytest.raises(ValueError, match="severity"):
            validate_config({"overrides": [{"title": "admin", "severity": severity}]})
    path = tmp_path / "rules.yaml"
    for text in ("ignore_titles: [first]\nignore_titles: [second]\n",
                 "overrides:\n  - title: first\n    title: second\n"):
        path.write_text(text, encoding="utf-8")
        with pytest.raises(ValueError, match="duplicate"):
            load_config(path)


def test_host_match_does_not_exclude_other_addresses_by_substring():
    assert len(apply_overrides([_finding()], {"exclusions": [{"host": "192.0.2"}]})) == 1


def test_config_rejects_boolean_match_patterns():
    import pytest

    from scanfuse.config import validate_config

    for key in ("title", "source_tool", "location", "host", "port", "cve", "tool_id"):
        for value in (True, False):
            with pytest.raises(ValueError, match=key):
                validate_config({"overrides": [{key: value, "severity": "High"}]})
