"""Regression tests for issues identified and resolved during the 1.0.0 audit loop."""

import json
from pathlib import Path

import pytest

from scanfuse.engine import ScanfuseEngine, csv_safe, md_escape, md_text
from scanfuse.models import Finding, Host
from scanfuse.parsers.base import html_to_text
from scanfuse.parsers.burp import BurpParser
from scanfuse.parsers.nessus import NessusParser
from scanfuse.parsers.nmap import NmapParser
from scanfuse.parsers.nuclei import NucleiParser
from scanfuse.parsers.trivy import TrivyParser
from scanfuse.parsers.zap import ZapParser
from scanfuse.utils import deduplicate_findings


def test_burp_critical_severity_mapped(tmp_path: Path) -> None:
    burp_xml = tmp_path / "burp_crit.xml"
    burp_xml.write_text("""<?xml version="1.0"?>
<issues burpVersion="2024.1">
  <issue>
    <serialNumber>1</serialNumber>
    <name>Critical RCE</name>
    <host ip="10.0.0.1">http://example.com</host>
    <severity>Critical</severity>
  </issue>
</issues>""", encoding="utf-8")
    findings = BurpParser().parse(str(burp_xml))
    assert len(findings) == 1
    assert findings[0].severity == "Critical"
    assert findings[0].port == "80/tcp"


def test_trivy_non_float_v3score_and_null_rule_id(tmp_path: Path) -> None:
    trivy_json = tmp_path / "trivy_edge.json"
    trivy_json.write_text(json.dumps({
        "SchemaVersion": 2,
        "ArtifactName": "test-artifact",
        "Results": [
            {
                "Target": "app",
                "Vulnerabilities": [
                    {"VulnerabilityID": "CVE-2024-0001", "Severity": "HIGH", "CVSS": {"nvd": {"V3Score": "N/A"}}},
                    {"VulnerabilityID": "CVE-2024-0002", "Severity": "HIGH", "CVSS": {"nvd": {"V3Score": float("nan")}}},
                ],
                "Secrets": [
                    {"RuleID": None, "Title": None, "Severity": "INFO"},
                    {"RuleID": "test-sec", "Title": "Secret Token", "Severity": "INFO"},
                ],
            }
        ]
    }), encoding="utf-8")
    findings = TrivyParser().parse(str(trivy_json))
    assert len(findings) == 4
    assert findings[0].cvss_score is None
    assert findings[1].cvss_score is None
    assert findings[2].title == "Unknown Secret"
    assert findings[2].severity == "Info"
    assert findings[3].severity == "Info"


def test_utf8_bom_support(tmp_path: Path) -> None:
    trivy_bom = tmp_path / "trivy_bom.json"
    trivy_bom.write_bytes(b"\xef\xbb\xbf" + json.dumps({
        "SchemaVersion": 2,
        "ArtifactName": "bom-test",
        "Results": [{"Target": "t1", "Vulnerabilities": [{"VulnerabilityID": "CVE-2024-BOM"}]}]
    }).encode("utf-8"))
    findings = TrivyParser().parse(str(trivy_bom))
    assert len(findings) == 1

    nuclei_bom = tmp_path / "nuclei_bom.jsonl"
    nuclei_bom.write_bytes(b"\xef\xbb\xbf" + json.dumps({
        "template-id": "bom-template",
        "info": {"name": "BOM Template", "severity": "info"}
    }).encode("utf-8") + b"\n")
    n_findings = NucleiParser().parse(str(nuclei_bom))
    assert len(n_findings) == 1
    assert n_findings[0].title == "BOM Template"


def test_zap_port_extraction_and_collision_prevention(tmp_path: Path) -> None:
    zap_xml = tmp_path / "zap_ports.xml"
    zap_xml.write_text("""<?xml version="1.0"?>
<OWASPZAPReport version="2.11.1">
  <site name="http://target.local:8080" host="target.local" port="8080">
    <alerts>
      <alertitem><pluginid>1</pluginid><name>Header Missing</name><riskcode>1</riskcode></alertitem>
    </alerts>
  </site>
  <site name="http://target.local:9090" host="target.local" port="9090">
    <alerts>
      <alertitem><pluginid>1</pluginid><name>Header Missing</name><riskcode>1</riskcode></alertitem>
    </alerts>
  </site>
</OWASPZAPReport>""", encoding="utf-8")
    findings = ZapParser().parse(str(zap_xml))
    assert len(findings) == 2
    assert findings[0].port == "8080/tcp"
    assert findings[1].port == "9090/tcp"
    merged = deduplicate_findings(findings)
    assert len(merged) == 2, "Findings on different ports must remain distinct"


def test_trivy_keeps_finding_with_non_string_cvss_vector(tmp_path: Path) -> None:
    source = tmp_path / "trivy.json"
    source.write_text(json.dumps({"SchemaVersion": 2, "Results": [{"Target": "x",
        "Vulnerabilities": [{"VulnerabilityID": "CVE-2024-0001",
            "CVSS": {"nvd": {"V3Score": 8.1, "V3Vector": {"bad": 1}}}}]}]}),
        encoding="utf-8")
    finding = TrivyParser().parse(str(source))[0]
    assert finding.cvss_score == 8.1
    assert finding.cvss_vector is None


def test_trivy_uses_valid_score_when_nvd_score_is_invalid(tmp_path: Path) -> None:
    source = tmp_path / "trivy-fallback.json"
    source.write_text(json.dumps({"SchemaVersion": 2, "Results": [{"Target": "x",
        "Vulnerabilities": [{"VulnerabilityID": "CVE-2024-0001", "CVSS": {
            "nvd": {"V3Score": "N/A"}, "vendor": {"V3Score": 7.2, "V3Vector": "vendor-vector"}
        }}]}]}), encoding="utf-8")
    finding = TrivyParser().parse(str(source))[0]
    assert finding.cvss_score == 7.2
    assert finding.cvss_vector == "vendor-vector"


def test_nessus_ipv6_tag(tmp_path: Path) -> None:
    nessus_xml = tmp_path / "nessus_v6.xml"
    nessus_xml.write_text("""<?xml version="1.0"?>
<NessusClientData_v2>
  <Report>
    <ReportHost name="server.example.local">
      <HostProperties>
        <tag name="host-ipv6">2001:db8::1</tag>
      </HostProperties>
      <ReportItem pluginID="100" pluginName="Test Plugin" severity="1" port="0" protocol="tcp">
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>""", encoding="utf-8")
    findings = NessusParser().parse(str(nessus_xml))
    assert len(findings) == 1
    assert findings[0].hosts[0].ip == "2001:db8::1"


def test_nessus_preserves_both_ip_addresses(tmp_path: Path) -> None:
    source = tmp_path / "dual-stack.nessus"
    source.write_text('''<NessusClientData_v2><Report><ReportHost name="example.test">
      <HostProperties>
        <tag name="host-ipv6">2001:db8::1</tag>
        <tag name="host-ip">192.0.2.1</tag>
        <tag name="host-fqdn">example.test</tag>
      </HostProperties>
      <ReportItem pluginID="100" pluginName="Test" severity="1" port="0" />
    </ReportHost></Report></NessusClientData_v2>''', encoding="utf-8")
    finding = NessusParser().parse(str(source))[0]
    assert {host.ip for host in finding.hosts} == {"192.0.2.1", "2001:db8::1"}
    assert all(host.hostname == "example.test" for host in finding.hosts)


def test_nmap_script_structured_children_and_open_filtered(tmp_path: Path) -> None:
    nmap_xml = tmp_path / "nmap_adv.xml"
    nmap_xml.write_text("""<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <hostnames>
      <hostname name="rev.cloud.com" type="PTR"/>
      <hostname name="target.client.com" type="user"/>
    </hostnames>
    <ports>
      <port protocol="udp" portid="53">
        <state state="open|filtered"/>
        <service name="domain"/>
        <script id="dns-info">
          <elem key="recursion">enabled</elem>
          <elem key="version">BIND 9</elem>
        </script>
      </port>
    </ports>
  </host>
</nmaprun>""", encoding="utf-8")
    findings = NmapParser().parse(str(nmap_xml))
    assert len(findings) == 1
    assert findings[0].hosts[0].hostname == "target.client.com"
    assert findings[0].port == "53/udp"
    assert "recursion: enabled" in findings[0].evidence[0].data
    assert "BIND 9" in findings[0].evidence[0].data


def test_empty_ignore_titles_does_not_drop_findings(tmp_path: Path) -> None:
    engine = ScanfuseEngine(str(tmp_path))
    f = Finding(title="SQL Injection", severity="High", description="test", source_tool="nmap")
    filtered = engine.filter_findings([f], ignore_rules=["", "   "])
    assert len(filtered) == 1


def test_host_deduplication_case_and_missing_hostname() -> None:
    f1 = Finding(
        title="Cross-Site Scripting",
        severity="High",
        description="d1",
        source_tool="tool1",
        hosts=[Host(ip="192.168.1.10", hostname="Web.Local")],
    )
    f2 = Finding(
        title="Cross-Site Scripting",
        severity="High",
        description="d2",
        source_tool="tool2",
        hosts=[Host(ip="192.168.1.10", hostname=None)],
    )
    merged = deduplicate_findings([f1, f2])
    assert len(merged) == 1
    assert len(merged[0].hosts) == 1
    assert merged[0].hosts[0].ip == "192.168.1.10"
    assert merged[0].hosts[0].hostname == "Web.Local"


def test_md_text_preserves_code_block_indentation() -> None:
    snippet = "Description:\n```python\ndef test():\n    x = 1\n    return x\n```"
    rendered = md_text(snippet)
    assert "    x = 1" in rendered
    assert "    return x" in rendered


def test_csv_safe_zero_width_bom() -> None:
    assert csv_safe("\ufeff=1+1").startswith("'")
    assert csv_safe("\u200b=cmd").startswith("'")


def test_html_to_text_table_cells() -> None:
    html = "<table><tr><td>Column1</td><td>Column2</td></tr></table>"
    text = html_to_text(html)
    assert "Column1 Column2" in text or "Column1  Column2" in text


def test_csv_safe_ascii_control_characters() -> None:
    for prefix in ("=", "+", "-", "@"):
        for ctrl in ("\x1c", "\x1d", "\x1e", "\x1f", "\x0b", "\x0c"):
            assert csv_safe(f"{ctrl}{prefix}1234").startswith("'")


def test_burp_parser_invalid_port(tmp_path: Path) -> None:
    burp_xml = tmp_path / "burp_invalid_port.xml"
    burp_xml.write_text("""<?xml version="1.0"?>
<issues burpVersion="2024.1">
  <issue>
    <serialNumber>1</serialNumber>
    <name>Invalid Port Issue</name>
    <host ip="10.0.0.1">http://example.com:999999</host>
    <severity>High</severity>
  </issue>
</issues>""", encoding="utf-8")
    findings = BurpParser().parse(str(burp_xml))
    assert len(findings) == 1
    assert findings[0].port is None


def test_trivy_parser_null_target(tmp_path: Path) -> None:
    trivy_json = tmp_path / "trivy_null_target.json"
    trivy_json.write_text(json.dumps({
        "SchemaVersion": 2,
        "ArtifactName": "test-artifact",
        "Results": [
            {
                "Target": None,
                "Vulnerabilities": [
                    {"VulnerabilityID": "CVE-2024-9999", "Severity": "HIGH", "Title": "Null Target Vuln"}
                ]
            }
        ]
    }), encoding="utf-8")
    findings = TrivyParser().parse(str(trivy_json))
    assert len(findings) == 1
    assert findings[0].evidence[0].data == "Unknown Target"


def test_detect_format_utf16(tmp_path: Path) -> None:
    engine = ScanfuseEngine(str(tmp_path))
    utf16_xml = tmp_path / "nmap_utf16.xml"
    content = '<?xml version="1.0"?><nmaprun></nmaprun>'
    utf16_xml.write_bytes(content.encode("utf-16"))
    fmt = engine._detect_format(str(utf16_xml))
    assert fmt == "nmap"


def test_models_cvss_score_nan_inf_rejected() -> None:
    import pytest
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        Finding(title="NaN test", severity="High", description="desc", cvss_score=float("nan"), source_tool="test")
    with pytest.raises(ValidationError):
        Finding(title="Inf test", severity="High", description="desc", cvss_score=float("inf"), source_tool="test")


def test_virtual_hosts_preserved_on_same_ip() -> None:
    f1 = Finding(
        title="SQL Injection",
        severity="High",
        description="d1",
        source_tool="tool1",
        hosts=[Host(ip="10.0.0.1", hostname="app.local")],
    )
    f2 = Finding(
        title="SQL Injection",
        severity="High",
        description="d2",
        source_tool="tool2",
        hosts=[Host(ip="10.0.0.1", hostname="api.local")],
    )
    merged = deduplicate_findings([f1, f2])
    assert len(merged) == 1
    assert len(merged[0].hosts) == 2
    hostnames = {h.hostname for h in merged[0].hosts}
    assert hostnames == {"app.local", "api.local"}


def test_host_deduplication_unknown_ip_commutativity() -> None:
    f1 = Finding(
        title="Vuln A",
        severity="Medium",
        description="d1",
        source_tool="tool1",
        hosts=[Host(ip="unknown", hostname="target.com")],
    )
    f2 = Finding(
        title="Vuln A",
        severity="Medium",
        description="d2",
        source_tool="tool2",
        hosts=[Host(ip="10.0.0.1", hostname="target.com")],
    )
    merged1 = deduplicate_findings([f1, f2])
    merged2 = deduplicate_findings([f2, f1])
    assert len(merged1[0].hosts) == 1
    assert len(merged2[0].hosts) == 1
    assert merged1[0].hosts[0].ip == "10.0.0.1"
    assert merged2[0].hosts[0].ip == "10.0.0.1"


def test_html_report_external_md_urls() -> None:
    from scanfuse.html_report import render_report_fragment
    snippet = "Check [Advisory](https://github.com/advisories/GHSA-1234.md) for details."
    html = render_report_fragment(snippet)
    assert 'href="https://github.com/advisories/GHSA-1234.md"' in html
    assert 'href="#https' not in html


def test_md_escape_multilevel_headings() -> None:
    import markdown
    escaped = md_escape("Title\n\n## Injected Heading\n### Subheading\n# Top Heading")
    rendered = markdown.markdown(escaped)
    assert "<h2>" not in rendered
    assert "<h3>" not in rendered
    assert "<h1>" not in rendered
    assert "<p>" in rendered


def test_trivy_parser_numeric_severity_and_target(tmp_path: Path) -> None:
    trivy_json = tmp_path / "trivy_numeric_sev.json"
    trivy_json.write_text(json.dumps({
        "SchemaVersion": 2,
        "ArtifactName": "num-test",
        "Results": [{
            "Target": 12345,
            "Vulnerabilities": [
                {"VulnerabilityID": "CVE-2024-0001", "Severity": 1}
            ],
            "Misconfigurations": [
                {"ID": "AVD-0001", "Severity": 2}
            ],
            "Secrets": [
                {"RuleID": "sec-0001", "Severity": 3}
            ]
        }]
    }), encoding="utf-8")
    findings = TrivyParser().parse(str(trivy_json))
    assert len(findings) == 3
    assert findings[0].evidence[0].data == "12345"
    assert findings[0].severity == "Info"
    assert findings[1].severity == "Info"
    assert findings[2].severity == "Critical"


def test_zap_parser_domain_hostname_and_deduplication(tmp_path: Path) -> None:
    zap_xml = tmp_path / "zap_domain.xml"
    zap_xml.write_text("""<?xml version="1.0"?>
<OWASPZAPReport version="2.11.1">
  <site name="https://example.com" host="example.com" port="443">
    <alerts>
      <alertitem><pluginid>1001</pluginid><name>CORS Misconfiguration</name><riskcode>2</riskcode></alertitem>
    </alerts>
  </site>
</OWASPZAPReport>""", encoding="utf-8")
    zap_findings = ZapParser().parse(str(zap_xml))
    assert len(zap_findings) == 1
    assert zap_findings[0].hosts[0].ip == "unknown"
    assert zap_findings[0].hosts[0].hostname == "example.com"

    other_finding = Finding(
        title="CORS Misconfiguration",
        severity="Medium",
        description="desc",
        source_tool="burp",
        port="443/tcp",
        hosts=[Host(ip="93.184.216.34", hostname="example.com")],
    )
    merged = deduplicate_findings([zap_findings[0], other_finding])
    assert len(merged) == 1
    assert len(merged[0].hosts) == 1
    assert merged[0].hosts[0].ip == "93.184.216.34"
    assert merged[0].hosts[0].hostname == "example.com"


def test_experimental_formats_are_not_auto_detected(tmp_path: Path) -> None:
    # SARIF, Semgrep, Grype, Nikto and testssl.sh are experimental and need --format.
    # Auto-detection only returns stable formats, so a Nuclei or Trivy file is never misread.
    padding = "X" * 80000
    sarif_file = tmp_path / "large.sarif"
    sarif_file.write_text(json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "Semgrep"}}, "results": [{"ruleId": "r1", "message": {"text": padding}}]}],
    }), encoding="utf-8")
    with pytest.raises(ValueError, match="--format sarif"):
        ScanfuseEngine._detect_format(str(sarif_file))

    for name, payload in {
        "semgrep": {"results": [{"check_id": "rule-1", "path": "app.py", "extra": {"message": padding}}]},
        "grype": {"matches": [{"vulnerability": {"id": "CVE-2024-1"}, "artifact": {"name": "p"}}]},
        "testssl": [{"id": "heartbleed", "ip": "192.0.2.1", "port": "443", "severity": "CRITICAL", "finding": "x"}],
    }.items():
        path = tmp_path / f"{name}.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        assert ScanfuseEngine._detect_format(str(path)) == "nuclei"

    nikto_xml = tmp_path / "nikto.xml"
    nikto_xml.write_text('<?xml version="1.0" ?><niktoscan host="example.com"><item id="1">'
                         '<description>test</description></item></niktoscan>', encoding="utf-8")
    with pytest.raises(ValueError, match="Use --format"):
        ScanfuseEngine._detect_format(str(nikto_xml))


def test_input_format_excludes_pdf() -> None:
    from scanfuse.cli import InputFormat
    assert "pdf" not in [f.value for f in InputFormat]



