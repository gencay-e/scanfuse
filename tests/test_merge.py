"""Merging findings must not lose information."""
import os

from scanfuse.engine import ScanfuseEngine
from scanfuse.models import Evidence, Finding, Host
from scanfuse.utils import deduplicate_findings

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def finding(title="SQL Injection", tool="zap", severity="High", **kwargs):
    kwargs.setdefault("description", f"{tool} description")
    return Finding(title=title, severity=severity, source_tool=tool, **kwargs)


def test_merged_finding_keeps_description_and_remediation_of_every_tool():
    a = finding(tool="zap", description="ZAP text", remediation="ZAP fix")
    b = finding(title="sql injection", tool="burp", description="Burp text", remediation="Burp fix")
    (merged,) = deduplicate_findings([a, b])
    assert merged.source_tool == "zap, burp"
    texts = {(s.source_tool, s.description, s.remediation) for s in merged.sources}
    assert texts == {("zap", "ZAP text", "ZAP fix"), ("burp", "Burp text", "Burp fix")}


def test_cvss_score_and_vector_are_not_discarded():
    burp = finding(tool="burp", cvss_score=8.0, cvss_vector="AV:N/A")
    zap = finding(tool="zap", cvss_score=7.0, cvss_vector="AV:N/B")
    nuclei = finding(tool="nuclei", severity="Critical")
    (merged,) = deduplicate_findings([burp, zap, nuclei])
    assert merged.severity == "Critical"
    assert (merged.cvss_score, merged.cvss_vector) == (8.0, "AV:N/A")
    assert {(s.source_tool, s.cvss_score, s.cvss_vector) for s in merged.sources} == {
        ("burp", 8.0, "AV:N/A"), ("zap", 7.0, "AV:N/B"), ("nuclei", None, None)}


def test_higher_severity_later_does_not_replace_the_first_description():
    low = finding(tool="zap", severity="Low", description="harmless")
    high = finding(tool="burp", severity="High", description="dangerous")
    (merged,) = deduplicate_findings([low, high])
    assert merged.severity == "High"
    assert {s.description for s in merged.sources} == {"harmless", "dangerous"}


def test_same_title_with_different_cves_stays_separate():
    a = finding(title="Vulnerable library", tool="trivy", identifiers=["CVE-2024-0001"])
    b = finding(title="Vulnerable library", tool="trivy", identifiers=["CVE-2024-0002"])
    assert len(deduplicate_findings([a, b])) == 2


def test_same_title_and_same_cve_from_two_tools_merges():
    a = finding(title="Vulnerable library", tool="trivy", identifiers=["CVE-2024-0001"])
    b = finding(title="vulnerable library", tool="nessus", identifiers=["cve-2024-0001"])
    assert len(deduplicate_findings([a, b])) == 1


def test_same_plugin_name_on_different_ports_stays_separate():
    a = finding(title="TLS weak cipher", tool="nessus", port="443/tcp")
    b = finding(title="TLS weak cipher", tool="nessus", port="8443/tcp")
    assert len(deduplicate_findings([a, b])) == 2


def test_different_tool_ids_of_the_same_tool_stay_separate():
    a = finding(title="Plugin", tool="nessus", identifiers=["nessus-plugin:1"])
    b = finding(title="Plugin", tool="nessus", identifiers=["nessus-plugin:2"])
    c = finding(title="Plugin", tool="zap", identifiers=["zap-plugin:9"])
    result = deduplicate_findings([a, b, c])
    assert len(result) == 2  # a and c merge, b is separate


def test_similar_non_numeric_identifiers_stay_separate():
    ids = ["GHSA-abcd-efgh-ijkl in pkg", "GHSA-abcd-efgh-ijkm in pkg", "/admin", "/admins"]
    assert len(deduplicate_findings([finding(title=t) for t in ids])) == 4


def test_hosts_with_different_os_keep_both_values():
    a = finding(tool="nmap", hosts=[Host(ip="10.0.0.1", os="Linux")])
    b = finding(tool="zap", hosts=[Host(ip="10.0.0.1", os="Windows")])
    (merged,) = deduplicate_findings([a, b])
    assert merged.hosts[0].os == "Linux / Windows"


def test_evidence_records_which_tool_reported_it():
    a = finding(tool="zap", evidence=[Evidence(type="http", data="one")])
    b = finding(tool="burp", evidence=[Evidence(type="http", data="two"),
                                       Evidence(type="http", data="one")])
    (merged,) = deduplicate_findings([a, b])
    by_data = {e.data: e.source for e in merged.evidence}
    assert by_data == {"one": "zap, burp", "two": "burp"}


def test_input_objects_are_not_modified():
    a = finding(tool="zap", hosts=[Host(ip="1.1.1.1")], evidence=[Evidence(type="t", data="x")])
    b = finding(tool="burp", hosts=[Host(ip="2.2.2.2")], severity="Critical")
    before = (a.model_dump(), b.model_dump())
    deduplicate_findings([a, b])
    assert (a.model_dump(), b.model_dump()) == before


def test_result_is_deterministic_and_follows_first_occurrence():
    items = [finding(title="B", tool="zap"), finding(title="A", tool="zap"),
             finding(title="b", tool="burp")]
    first = [f.model_dump() for f in deduplicate_findings(items)]
    second = [f.model_dump() for f in deduplicate_findings(items)]
    assert first == second
    assert [f["title"] for f in first] == ["B", "A"]


def test_many_distinct_titles_are_all_kept():
    items = [finding(title=f"Distinct finding {i}x", tool="zap") for i in range(6000)]
    assert len(deduplicate_findings(items)) == 6000


def test_unmerged_finding_has_no_sources():
    (single,) = deduplicate_findings([finding()])
    assert single.sources == []


def test_fixtures_zap_and_burp_sql_injection_keep_both_descriptions(tmp_path):
    engine = ScanfuseEngine(str(tmp_path))
    findings = []
    for name, fmt in (("dummy_zap.xml", "zap"), ("dummy_burp.xml", "burp")):
        findings += engine.process_file(os.path.join(FIXTURES, name), fmt)
    merged = [f for f in deduplicate_findings(findings) if f.sources]
    assert merged, "expected the SQL injection findings of ZAP and Burp to merge"
    for m in merged:
        original = [f for f in findings if f.title.strip().casefold() == m.title.strip().casefold()]
        assert {s.description for s in m.sources} == {f.description for f in original}
        assert {s.remediation for s in m.sources} == {f.remediation for f in original}
