import json

import pytest
from typer.testing import CliRunner

from scanfuse.cli import app
from scanfuse.parsers.nuclei import NucleiParser
from scanfuse.parsers.trivy import TrivyParser


@pytest.mark.parametrize("vector", [{"some": "dict"}, ["CVSS:3.1"], 123, None])
def test_nuclei_invalid_optional_vector_preserves_finding(tmp_path, vector):
    source = tmp_path / "nuclei.json"
    source.write_text(json.dumps({
        "template-id": "test-template",
        "info": {
            "name": "Test finding", "severity": "high",
            "classification": {"cvss-score": 7.5, "cvss-metrics": vector},
        },
        "ip": "192.0.2.1", "matched-at": "https://192.0.2.1/",
    }), encoding="utf-8")

    findings = NucleiParser().parse(str(source))
    assert len(findings) == 1
    assert findings[0].title == "Test finding"
    assert findings[0].severity == "High"
    assert findings[0].cvss_score == 7.5
    assert findings[0].cvss_vector is None
    assert findings[0].hosts[0].ip == "192.0.2.1"
    assert "https://192.0.2.1/" in findings[0].evidence[0].data


@pytest.mark.parametrize("lines", [123, "invalid", {"Content": "invalid"}, None, []])
def test_trivy_invalid_optional_lines_preserve_finding(tmp_path, lines):
    source = tmp_path / "trivy.json"
    source.write_text(json.dumps({
        "SchemaVersion": 2, "ArtifactName": "test-project",
        "Results": [{"Target": "main.tf", "Misconfigurations": [{
            "ID": "TEST-001", "Title": "Test misconfiguration", "Severity": "HIGH",
            "CauseMetadata": {"Provider": "aws", "Service": "s3", "Code": {"Lines": lines}},
        }]}],
    }), encoding="utf-8")

    findings = TrivyParser().parse(str(source))
    assert len(findings) == 1
    assert findings[0].title == "Test misconfiguration"
    assert findings[0].severity == "High"
    assert findings[0].hosts[0].hostname == "test-project"
    assert findings[0].evidence[0].data == "main.tf"
    assert "Provider: aws" in findings[0].evidence[1].data
    assert "Service: s3" in findings[0].evidence[1].data
    assert "Code snippet:" not in findings[0].evidence[1].data


def test_trivy_valid_code_lines_preserved(tmp_path):
    source = tmp_path / "trivy.json"
    source.write_text(json.dumps({
        "SchemaVersion": 2,
        "Results": [{"Misconfigurations": [{"CauseMetadata": {"Code": {
            "Lines": [{"Content": "resource aws_s3_bucket"}, None, {"Content": "acl = public"}],
        }}}]}],
    }), encoding="utf-8")
    finding = TrivyParser().parse(str(source))[0]
    assert "Code snippet:\nresource aws_s3_bucket\nacl = public" in finding.evidence[1].data


@pytest.mark.parametrize("format_hint, payload", [
    ("nuclei", {"info": {"classification": {"cvss-metrics": {"some": "dict"}}}}),
    ("trivy", {"SchemaVersion": 2, "Results": [{"Misconfigurations": [{
        "CauseMetadata": {"Code": {"Lines": 123}},
    }]}]}),
])
def test_cli_exports_findings_with_malformed_optional_metadata(tmp_path, format_hint, payload):
    source = tmp_path / "scan.json"
    source.write_text(json.dumps(payload), encoding="utf-8")
    output = tmp_path / "report"
    result = CliRunner().invoke(app, [str(source), "--format", format_hint,
                                    "--format-out", "json", "--output", str(output)])
    assert result.exit_code == 0, result.stdout
    exported = json.loads((output / "report.json").read_text(encoding="utf-8"))["findings"]
    assert len(exported) == 1
    assert exported[0]["source_tool"] == format_hint
