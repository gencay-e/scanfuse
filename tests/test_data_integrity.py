import csv

import pytest

from scanfuse.engine import ScanfuseEngine
from scanfuse.models import Evidence, Finding, Host
from scanfuse.parsers.nmap import NmapParser
from scanfuse.utils import deduplicate_findings


def make_finding(title="Same title", **kwargs):
    return Finding(title=title, severity=kwargs.pop("severity", "Info"),
                   description="Description", source_tool=kwargs.pop("source_tool", "nmap"), **kwargs)


@pytest.mark.parametrize("first, second", [
    ("Open Port: 10000/tcp (http)", "Open Port: 10001/tcp (http)"),
    ("CVE-2026-12345 in package", "CVE-2026-12346 in package"),
    ("TLS 1.2 protocol enabled", "TLS 1.3 protocol enabled"),
])
def test_different_numeric_identifiers_are_separate_findings(first, second):
    result = deduplicate_findings([make_finding(first), make_finding(second)])
    assert [f.title for f in result] == [first, second]


def test_similar_titles_are_not_merged():
    result = deduplicate_findings([make_finding("Open Port: 443/tcp (https)"),
                                   make_finding("Open Port: 443/tcp (https).")])
    assert len(result) == 2


def test_titles_equal_ignoring_case_and_space_are_merged():
    result = deduplicate_findings([make_finding("SQL Injection"), make_finding("  sql injection ")])
    assert len(result) == 1


def test_large_exact_group_preserves_unique_hosts_and_evidence():
    findings = [make_finding(hosts=[Host(ip=f"host-{i}")],
                             evidence=[Evidence(type="scan", data=f"evidence-{i}")])
                for i in range(20000)]
    findings.append(make_finding(hosts=[Host(ip="host-0", os="Linux")],
                                 evidence=[Evidence(type="scan", data="evidence-0")],
                                 severity="High", source_tool="zap", cvss_score=7.5))
    result = deduplicate_findings(findings)
    assert len(result) == 1
    merged = result[0]
    assert [h.ip for h in merged.hosts] == [f"host-{i}" for i in range(20000)]
    assert merged.hosts[0].os == "Linux"
    assert [e.data for e in merged.evidence] == [f"evidence-{i}" for i in range(20000)]
    assert merged.severity == "High"
    assert merged.cvss_score == 7.5
    assert merged.source_tool == "nmap, zap"


@pytest.mark.parametrize("prefix", ["=", "+", "-", "@", "\t", "\r", "\n", " ", "\n=", " \t="])
def test_csv_neutralizes_formula_prefixes_in_scanner_fields(tmp_path, prefix):
    payload = prefix + "test"
    finding = Finding(title=payload, severity="High", description=payload,
                      remediation=payload, source_tool=payload, hosts=[Host(ip=payload)])
    ScanfuseEngine(str(tmp_path)).export_csv([finding])
    with (tmp_path / "report.csv").open(newline="", encoding="utf-8") as stream:
        rows = list(csv.reader(stream))
    assert len(rows) == 2
    for index in [0, 3, 4, 5, 6]:
        assert rows[1][index] == "'" + payload


def test_csv_preserves_quotes_multiline_evidence_and_zero_score(tmp_path):
    finding = make_finding('Title, "quoted"', cvss_score=0.0,
                           evidence=[Evidence(type="response", data='Line 1\nLine 2, "quoted"')])
    ScanfuseEngine(str(tmp_path)).export_csv([finding])
    with (tmp_path / "report.csv").open(newline="", encoding="utf-8") as stream:
        rows = list(csv.reader(stream))
    assert rows[1][0] == 'Title, "quoted"'
    assert rows[1][2] == "0.0"
    assert rows[1][7] == 'response:\nLine 1\nLine 2, "quoted"'


def test_large_nmap_xml_preserves_every_host_and_port(tmp_path):
    source = tmp_path / "large.xml"
    with source.open("w", encoding="utf-8") as stream:
        stream.write("<nmaprun>")
        for index in range(10000):
            stream.write(f'<host><status state="up"/><address addr="host-{index}" addrtype="ipv4"/>'
                         '<ports><port protocol="tcp" portid="443"><state state="open"/>'
                         '<service name="https"/></port></ports></host>')
        stream.write("</nmaprun>")
    findings = NmapParser().parse(str(source))
    assert len(findings) == 10000
    assert [f.hosts[0].ip for f in findings] == [f"host-{i}" for i in range(10000)]
    assert all(f.title == "Open Port: 443/tcp (https)" for f in findings)
    merged = deduplicate_findings(findings)
    assert len(merged) == 1
    assert len(merged[0].hosts) == 10000
    assert len(merged[0].evidence) == 1
