"""Parsers keep the ids and ports that identify a finding."""
import json
import os

from scanfuse.engine import ScanfuseEngine

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def parse(path, fmt, tmp_path):
    return ScanfuseEngine(str(tmp_path)).process_file(str(path), fmt)


def test_fixture_ids_and_ports(tmp_path):
    def ids(name, fmt):
        return [f.identifiers for f in parse(os.path.join(FIXTURES, name), fmt, tmp_path)]

    assert ids("dummy_zap.xml", "zap")[1] == ["zap-plugin:40018"]
    assert ids("dummy_burp.xml", "burp") == [["burp-type:8389632"]]
    assert ids("dummy_nessus.xml", "nessus") == [["nessus-plugin:12345"]]
    assert ids("dummy_trivy.json", "trivy")[0] == ["CVE-2022-28391"]
    nmap = parse(os.path.join(FIXTURES, "dummy_nmap_clean.xml"), "nmap", tmp_path)
    assert [f.port for f in nmap] == ["80/tcp", "443/tcp"]
    nessus = parse(os.path.join(FIXTURES, "dummy_nessus.xml"), "nessus", tmp_path)
    assert nessus[0].port == "443/tcp"


def test_nuclei_cve_and_cwe_ids(tmp_path):
    source = tmp_path / "n.json"
    source.write_text(json.dumps({
        "template-id": "t-1",
        "info": {"name": "N", "severity": "high",
                 "classification": {"cve-id": ["CVE-2024-1111", "cve-2024-2222"],
                                    "cwe-id": ["CWE-79", "89"]}},
        "host": "10.0.0.1"}), encoding="utf-8")
    (finding,) = parse(source, "nuclei", tmp_path)
    assert finding.identifiers == ["nuclei-template:t-1", "CVE-2024-1111", "CVE-2024-2222",
                                   "CWE-79", "CWE-89"]


def test_nessus_cve_elements(tmp_path):
    source = tmp_path / "n.nessus"
    source.write_text(
        '<NessusClientData_v2><Report><ReportHost name="10.0.0.1"><HostProperties>'
        '<tag name="host-ip">10.0.0.1</tag></HostProperties>'
        '<ReportItem port="22" protocol="tcp" pluginID="55" pluginName="SSH" severity="2">'
        '<cve>CVE-2023-0001</cve><cve>CVE-2023-0002</cve><description>d</description>'
        '</ReportItem></ReportHost></Report></NessusClientData_v2>', encoding="utf-8")
    (finding,) = parse(source, "nessus", tmp_path)
    assert finding.identifiers == ["nessus-plugin:55", "CVE-2023-0001", "CVE-2023-0002"]
    assert finding.port == "22/tcp"


def test_trivy_cwe_ids(tmp_path):
    source = tmp_path / "t.json"
    source.write_text(json.dumps({"SchemaVersion": 2, "ArtifactName": "img", "Results": [
        {"Target": "t", "Vulnerabilities": [
            {"VulnerabilityID": "CVE-2024-0009", "PkgName": "p", "Severity": "HIGH",
             "CweIDs": ["CWE-787"]}]}]}), encoding="utf-8")
    (finding,) = parse(source, "trivy", tmp_path)
    assert finding.identifiers == ["CVE-2024-0009", "CWE-787"]
