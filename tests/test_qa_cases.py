import json

import pytest
from typer.testing import CliRunner

from scanfuse.cli import app
from scanfuse.engine import ScanfuseEngine


@pytest.mark.parametrize("format_hint, payload, expected", [
    ("nessus", "<NessusClientData_v2/>", []),
    ("nmap", '<nmaprun><host><address addr="10.0.0.1" addrtype="ipv4"/>'
     '<ports><port protocol="tcp" portid="abc"><state state="open"/></port>'
     '</ports></host></nmaprun>', [("Open Port: abc/tcp (unknown)", "Info", 1)]),
    ("zap", '<OWASPZAPReport><site host="1.1.1.1"><alerts><alertitem/>'
     '</alerts></site></OWASPZAPReport>', [("Unknown Vulnerability", "Info", 0)]),
    ("zap", '<OWASPZAPReport><site host="1.1.1.1"><alerts><alertitem><instances>'
     '<instance><uri/><method/><evidence/></instance></instances></alertitem>'
     '</alerts></site></OWASPZAPReport>', [("Unknown Vulnerability", "Info", 0)]),
    ("burp", '<issues><issue><name>Test</name><host ip="1.2.3.4">target</host>'
     '<requestresponse><request base64="true">INVALID_BASE64_!!!</request>'
     '<response base64="true">!@#$</response></requestresponse></issue></issues>',
     [("Test", "Info", 1)]),
    ("trivy", json.dumps({"SchemaVersion": 2, "ArtifactName": "test", "Results": [{
        "Vulnerabilities": [{"VulnerabilityID": "CVE-1", "CVSS": {"nvd": "V3Score"}}],
    }]}), [("CVE-1 in ", "Info", 1)]),
    ("trivy", json.dumps({"SchemaVersion": 2, "ArtifactName": "test", "Results": [{
        "Misconfigurations": [{"ID": "MISC-1", "CauseMetadata": "Some string cause"}],
    }]}), [("MISC-1", "Info", 2)]),
    ("trivy", json.dumps({"SchemaVersion": 2, "ArtifactName": "test", "Results": [{
        "Vulnerabilities": [{"VulnerabilityID": "CVE-1", "Severity": None}],
    }]}), [("CVE-1 in ", "Info", 1)]),
])
def test_existing_qa_cases_export_without_data_loss(tmp_path, monkeypatch, format_hint, payload, expected):
    monkeypatch.chdir(tmp_path)
    source = tmp_path / "scan"
    source.write_text(payload, encoding="utf-8")
    output = tmp_path / "report"
    findings = ScanfuseEngine(str(output)).process_file(str(source), format_hint)
    assert [(f.title, f.severity, len(f.evidence)) for f in findings] == expected
    result = CliRunner().invoke(app, [str(source), "-f", format_hint,
                                    "--format-out", "json", "-o", str(output)])
    assert result.exit_code == 0, result.stdout
    if not expected:
        assert not output.exists()
        return
    exported = json.loads((output / "report.json").read_text(encoding="utf-8"))["findings"]
    assert exported == [f.model_dump() for f in findings]
    if format_hint == "burp":
        assert "INVALID_BASE64_!!!" in exported[0]["evidence"][0]["data"]
    if "Some string cause" in payload:
        assert exported[0]["evidence"][1]["data"] == "Some string cause"


def test_ignore_title_string_config_filters_only_matching_findings(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".scanfuse.yaml").write_text('ignore_titles: "Ignored"', encoding="utf-8")
    source = tmp_path / "scan.json"
    source.write_text('\n'.join(json.dumps({"info": {"name": title}})
                                 for title in ["Ignored alert", "Retained alert"]), encoding="utf-8")
    output = tmp_path / "report"
    result = CliRunner().invoke(app, [str(source), "-f", "nuclei", "--format-out", "json",
                                    "-o", str(output)])
    assert result.exit_code == 0, result.stdout
    exported = json.loads((output / "report.json").read_text(encoding="utf-8"))["findings"]
    assert [f["title"] for f in exported] == ["Retained alert"]
