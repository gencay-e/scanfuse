"""Optional acceptance checks against a real Windows build (set SCANFUSE_EXE)."""

import csv
import json
import os
import subprocess
from pathlib import Path

import pytest

from scanfuse.engine import ScanfuseEngine
from scanfuse.utils import deduplicate_findings

pytestmark = pytest.mark.skipif(not os.environ.get("SCANFUSE_EXE"), reason="SCANFUSE_EXE is not set")


def run_exe(tmp_path, args):
    executable = Path(os.environ["SCANFUSE_EXE"]).resolve()
    assert executable.is_file()
    env = os.environ.copy()
    env["TEMP"] = str(tmp_path)
    env["TMP"] = str(tmp_path)
    # SCANFUSE_EXE explicitly selects the local build under acceptance testing.
    result = subprocess.run([str(executable), *args], cwd=tmp_path, env=env,  # noqa: S603
                            capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stdout + result.stderr
    return result


@pytest.mark.parametrize("format_hint, filename", [
    ("nmap", "dummy_nmap_clean.xml"), ("nuclei", "dummy_nuclei.json"),
    ("zap", "dummy_zap.xml"), ("burp", "dummy_burp.xml"),
    ("nessus", "dummy_nessus.xml"), ("trivy", "dummy_trivy.json"),
])
def test_packaged_parsers_match_source(tmp_path, fixtures_dir, format_hint, filename):
    source = fixtures_dir / filename
    output = tmp_path / "report"
    expected = deduplicate_findings(ScanfuseEngine(str(output)).process_file(str(source), format_hint))
    run_exe(tmp_path, [str(source), "-f", format_hint, "--format-out", "json", "-o", str(output)])
    exported = json.loads((output / "report.json").read_text(encoding="utf-8"))["findings"]
    assert exported == [finding.model_dump() for finding in expected]


def test_packaged_html_contains_templates_and_sanitizer(tmp_path):
    source = tmp_path / "scan.json"
    source.write_text(json.dumps({"info": {
        "name": "Build finding", "severity": "high",
        "description": "[click](javascript:alert%281%29)\n\n**Safe text**",
        "classification": {"cvss-metrics": {"bad": "type"}},
    }}), encoding="utf-8")
    output = tmp_path / "report"
    run_exe(tmp_path, [str(source), "-f", "nuclei", "-o", str(output)])
    assert (output / "build-finding.md").exists()
    assert (output / "index.md").exists()
    html = (output / "report.html").read_text(encoding="utf-8")
    assert "Pentest Report Summary" in html
    assert "<table>" in html
    assert "<strong>Safe text</strong>" in html
    assert 'href="javascript:' not in html
    assert "function filterFindings()" in html


def test_packaged_trivy_regression_and_yaml_config(tmp_path):
    (tmp_path / ".scanfuse.yaml").write_text('ignore_titles: ["Ignored"]', encoding="utf-8")
    source = tmp_path / "scan.json"
    source.write_text(json.dumps({"SchemaVersion": 2, "Results": [{"Misconfigurations": [
        {"Title": "Retained", "CauseMetadata": {"Code": {"Lines": 123}}},
        {"Title": "Ignored"},
    ]}]}), encoding="utf-8")
    output = tmp_path / "report"
    run_exe(tmp_path, [str(source), "-f", "trivy", "--format-out", "json", "-o", str(output)])
    exported = json.loads((output / "report.json").read_text(encoding="utf-8"))["findings"]
    assert [finding["title"] for finding in exported] == ["Retained"]


def test_packaged_distinct_port_findings_remain_separate(tmp_path):
    source = tmp_path / "scan.xml"
    source.write_text('<nmaprun><host><address addr="192.0.2.1" addrtype="ipv4"/><ports>'
                      + ''.join(f'<port protocol="tcp" portid="{port}"><state state="open"/>'
                                '<service name="http"/></port>' for port in [10000, 10001])
                      + '</ports></host></nmaprun>', encoding="utf-8")
    output = tmp_path / "report"
    run_exe(tmp_path, [str(source), "--format-out", "json", "-o", str(output)])
    exported = json.loads((output / "report.json").read_text(encoding="utf-8"))["findings"]
    assert [finding["title"] for finding in exported] == [
        "Open Port: 10000/tcp (http)", "Open Port: 10001/tcp (http)",
    ]


def test_packaged_csv_neutralizes_formula_prefix(tmp_path):
    source = tmp_path / "scan.json"
    source.write_text(json.dumps({"info": {"name": "=1+1"}, "ip": "\n=1+1"}), encoding="utf-8")
    output = tmp_path / "report"
    run_exe(tmp_path, [str(source), "-f", "nuclei", "--format-out", "csv", "-o", str(output)])
    with (output / "report.csv").open(newline="", encoding="utf-8") as stream:
        rows = list(csv.reader(stream))
    assert rows[1][0] == "'=1+1"
    assert rows[1][3] == "'\n=1+1"
