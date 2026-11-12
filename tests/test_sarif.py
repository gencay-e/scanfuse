import json

from typer.testing import CliRunner

from scanfuse.cli import app
from scanfuse.engine import ScanfuseEngine
from scanfuse.models import Finding, Host, Observation
from scanfuse.parsers.sarif import SarifParser


def _sarif() -> dict:
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "Semgrep", "rules": [{
                "id": "python.lang.security.audit.eval-detected",
                "name": "Dangerous eval",
                "help": {"text": "Avoid eval.", "markdown": "Avoid eval."},
                "helpUri": "https://example.test/rule",
                "properties": {"security-severity": "8.0"},
            }]}},
            "results": [{
                "ruleId": "python.lang.security.audit.eval-detected",
                "level": "error",
                "message": {"text": "eval() was detected"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": "https://192.0.2.10/app.py"},
                    "region": {"startLine": 12},
                }}],
            }],
        }],
    }


def test_sarif_parser_maps_rule_result_and_location(tmp_path):
    path = tmp_path / "scan.sarif"
    path.write_text(json.dumps(_sarif()), encoding="utf-8")
    finding = SarifParser().parse(str(path))[0]
    assert finding.title == "Dangerous eval"
    assert "eval() was detected" in finding.description
    assert finding.severity == "High"
    assert finding.source_tool == "Semgrep"
    assert finding.hosts[0].ip == "192.0.2.10"
    assert finding.evidence[0].data.endswith(":12")
    assert finding.references == ["https://example.test/rule"]


def test_sarif_explicit_format_and_export(tmp_path):
    source = tmp_path / "scan.sarif"
    source.write_text(json.dumps(_sarif()), encoding="utf-8")
    output = tmp_path / "report"
    findings = ScanfuseEngine(str(output)).process_file(str(source), "sarif")
    ScanfuseEngine(str(output)).export_sarif(findings)
    exported = json.loads((output / "report.sarif").read_text(encoding="utf-8"))
    assert exported["version"] == "2.1.0"
    assert exported["runs"][0]["results"][0]["ruleId"] == findings[0].identifiers[0]


def test_cli_accepts_sarif_output(tmp_path):
    source = tmp_path / "scan.sarif"
    source.write_text(json.dumps(_sarif()), encoding="utf-8")
    result = CliRunner().invoke(app, [str(source), "--format", "sarif",
                                      "--format-out", "sarif", "-o", str(tmp_path / "out")])
    assert result.exit_code == 0, result.stdout
    assert (tmp_path / "out" / "report.sarif").exists()


def test_sarif_markdown_title_and_rule_collisions_are_preserved(tmp_path):
    data = _sarif()
    data["runs"][0]["results"][0]["message"] = {"markdown": "**markdown title**"}
    data["runs"][0]["results"].append({
        "message": {"text": "second"},
        "locations": [],
    })
    source = tmp_path / "scan.sarif"
    source.write_text(json.dumps(data), encoding="utf-8")
    findings = SarifParser().parse(str(source))
    assert findings[0].title == "Dangerous eval"
    assert "**markdown title**" in findings[0].description
    assert findings[1].title == "second"
    output = tmp_path / "report"
    ScanfuseEngine(str(output)).export_sarif(findings)
    exported = json.loads((output / "report.sarif").read_text(encoding="utf-8"))
    rule_ids = [result["ruleId"] for result in exported["runs"][0]["results"]]
    assert len(rule_ids) == len(set(rule_ids))
    assert exported["runs"][0]["results"][0]["properties"]["references"]


def test_sarif_export_preserves_description_and_all_references(tmp_path):
    finding = Finding(
        title="Title", severity="Low", description="Long description",
        remediation="Fix it", source_tool="test", identifiers=["CWE-79"],
        references=["https://example.test/a", "https://example.test/b"],
    )
    output = tmp_path / "report"
    ScanfuseEngine(str(output)).export_sarif([finding])
    data = json.loads((output / "report.sarif").read_text(encoding="utf-8"))
    rule = data["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["fullDescription"]["text"] == "Long description"
    assert rule["properties"]["references"] == finding.references


def test_sarif_export_structure_follows_the_2_1_0_schema_for_locations(tmp_path):
    # The log was also checked against the official sarif-schema-2.1.0.json by hand;
    # the schema is not part of the package, so this checks the shape that matters.
    finding = Finding(
        title="T", severity="High", description="d", source_tool="zap", identifiers=["CWE-79"],
        hosts=[Host(ip="10.0.0.1", hostname="a.test"), Host(ip="unknown", hostname="b.test")],
        observations=[Observation(host="10.0.0.1", method="GET", location="/x", source_tool="zap")],
    )
    output = tmp_path / "report"
    ScanfuseEngine(str(output)).export_sarif([finding])
    data = json.loads((output / "report.sarif").read_text(encoding="utf-8"))
    assert data["version"] == "2.1.0" and data["$schema"].endswith("sarif-2.1.0.json")
    (result,) = data["runs"][0]["results"]
    assert result["ruleId"] == "CWE-79" and result["message"]["text"] == "T"
    assert result["locations"] == [
        {"logicalLocations": [{"name": "10.0.0.1 (a.test)", "kind": "resource"}]},
        {"logicalLocations": [{"name": "b.test", "kind": "resource"}]},
    ]
    assert result["properties"]["observations"][0]["location"] == "/x"
