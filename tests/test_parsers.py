import json
import os

import pytest

from scanfuse.parsers.base import PartialImportError
from scanfuse.parsers.burp import BurpParser
from scanfuse.parsers.nessus import NessusParser
from scanfuse.parsers.nmap import NmapParser
from scanfuse.parsers.nuclei import NucleiParser
from scanfuse.parsers.zap import ZapParser


def test_nuclei_array_reports_invalid_finding_as_partial(tmp_path):
    path = tmp_path / "nuclei.json"
    path.write_text(json.dumps([
        {"template-id": "good", "info": {"name": "good"}},
        {"template-id": "bad", "host": {"unexpected": "object"}},
    ]), encoding="utf-8")
    with pytest.raises(PartialImportError) as exc:
        NucleiParser().parse(str(path))
    assert [finding.title for finding in exc.value.findings] == ["good"]


def test_nuclei_keeps_findings_with_non_string_optional_text(tmp_path):
    path = tmp_path / "nuclei.json"
    path.write_text(json.dumps([{
        "template-id": "item", "info": {"description": [1, 2], "remediation": 123},
    }]), encoding="utf-8")
    finding = NucleiParser().parse(str(path))[0]
    assert finding.title == "item"
    assert finding.description == "[1, 2]"
    assert finding.remediation == "123"

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")
NMAP_CLEAN_XML = os.path.join(FIXTURES_DIR, "dummy_nmap_clean.xml")
NMAP_DIRTY_XML = os.path.join(FIXTURES_DIR, "dummy_nmap_dirty.xml")
NUCLEI_JSON = os.path.join(FIXTURES_DIR, "dummy_nuclei.json")

def test_nmap_parser_clean():
    parser = NmapParser()
    findings = parser.parse(NMAP_CLEAN_XML)

    assert len(findings) == 2

    f1 = findings[0]
    assert f1.title == "Open Port: 80/tcp (http (Apache httpd 2.4.41))"
    assert f1.severity == "Info"
    assert f1.source_tool == "nmap"
    assert len(f1.hosts) == 1
    assert f1.hosts[0].ip == "192.168.1.10"
    assert f1.hosts[0].hostname == "target.local"

    assert len(f1.evidence) == 1
    assert f1.evidence[0].type == "port-scan"
    assert "Port: 80/tcp" in f1.evidence[0].data
    assert "Script http-title: Welcome to VulnApp" in f1.evidence[0].data

    f2 = findings[1]
    assert f2.title == "Open Port: 443/tcp (https (nginx 1.18.0))"

def test_nmap_parser_dirty():
    parser = NmapParser()
    findings = parser.parse(NMAP_DIRTY_XML)

    # Port 22 is filtered -> skipped
    # Port 3306 is open -> finding created
    assert len(findings) == 1

    f = findings[0]
    assert f.title == "Open Port: 3306/tcp (mysql)"
    assert f.hosts[0].ip == "10.0.0.5"
    assert f.hosts[0].hostname is None

def test_nuclei_parser():
    parser = NucleiParser()
    findings = parser.parse(NUCLEI_JSON)

    assert len(findings) == 2

    f1 = findings[0]
    assert f1.title == "Apache 2.4.49/2.4.50 - Path Traversal"
    assert f1.severity == "Critical"
    assert f1.cvss_score == 9.8
    assert f1.cvss_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert f1.hosts[0].ip == "192.168.1.10"
    assert f1.source_tool == "nuclei"

    assert len(f1.evidence) == 1
    assert f1.evidence[0].type == "http-request"
    assert "GET /cgi-bin" in f1.evidence[0].data
    assert "root:x:0:0:root" in f1.evidence[0].data

    f2 = findings[1]
    assert f2.title == "Wappalyzer Technology Detection"
    assert f2.severity == "Info"
    assert len(f2.evidence) == 1
    assert f2.evidence[0].type == "match"
    assert "https://192.168.1.10:443/" in f2.evidence[0].data

ZAP_XML = os.path.join(FIXTURES_DIR, "dummy_zap.xml")

def test_zap_parser():
    parser = ZapParser()
    findings = parser.parse(ZAP_XML)

    assert len(findings) == 2

    f1 = findings[0]
    assert f1.title == "X-Content-Type-Options Header Missing"
    assert f1.severity == "Low"
    assert f1.source_tool == "zap"
    assert f1.hosts[0].ip == "192.168.1.20"
    assert len(f1.evidence) == 1
    assert "POST http://192.168.1.20/api/login" in f1.evidence[0].data

    f2 = findings[1]
    assert f2.title == "SQL Injection"
    assert f2.severity == "High"
    assert "SQL syntax error" in f2.evidence[0].data


def test_zap_preserves_payload_html_and_query_in_location(tmp_path):
    source = tmp_path / "zap.xml"
    source.write_text('''<OWASPZAPReport><site host="example.test"><alerts><alertitem>
      <alert>Test</alert><riskcode>2</riskcode><uri>https://example.test/search?q=1</uri>
      <param>&lt;img src=x onerror=alert(1)&gt;</param><attack>&lt;script&gt;alert(1)&lt;/script&gt;</attack>
      <evidence>&lt;b&gt;matched&lt;/b&gt;</evidence></alertitem></alerts></site></OWASPZAPReport>''', encoding="utf-8")
    finding = ZapParser().parse(str(source))[0]
    assert finding.observations[0].location == "/search?q=1 [<img src=x onerror=alert(1)> parameter]"
    assert "Attack: <script>alert(1)</script>" in finding.evidence[0].data
    assert "Evidence: <b>matched</b>" in finding.evidence[0].data


def test_burp_url_host_and_empty_ip_fallback(tmp_path):
    source = tmp_path / "burp.xml"
    source.write_text('<issues><issue><name>Test</name><host ip="">https://example.test:8443/path</host></issue></issues>', encoding="utf-8")
    finding = BurpParser().parse(str(source))[0]
    assert finding.hosts[0].ip == "unknown"
    assert finding.hosts[0].hostname == "example.test"
    assert finding.port == "8443/tcp"


def test_nessus_reporthost_name_falls_back_to_hostname(tmp_path):
    source = tmp_path / "nessus.xml"
    source.write_text('<NessusClientData_v2><Report><ReportHost name="scanner.example"><ReportItem pluginName="Test" severity="1" port="0" protocol="tcp" /></ReportHost></Report></NessusClientData_v2>', encoding="utf-8")
    finding = NessusParser().parse(str(source))[0]
    assert finding.hosts[0].ip == "unknown"
    assert finding.hosts[0].hostname == "scanner.example"
