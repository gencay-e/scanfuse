"""Merging findings must not lose information."""
import os

from scanfuse.engine import ScanfuseEngine
from scanfuse.models import Evidence, Finding, Host, Observation
from scanfuse.utils import deduplicate_findings

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def finding(title="SQL Injection", tool="zap", severity="High", location=None, method=None,
            places=None, **kwargs):
    """`location` and `method` give one observation; `places` is a list of (method, location)."""
    kwargs.setdefault("description", f"{tool} description")
    pairs = places if places is not None else ([(method, location)] if location or method else [])
    host = kwargs["hosts"][0].ip if kwargs.get("hosts") else None
    kwargs["observations"] = [
        Observation(host=host, method=m, location=loc, source_tool=tool) for m, loc in pairs
    ]
    return Finding(title=title, severity=severity, source_tool=tool, **kwargs)


def parse_zap(tmp_path, body, host="example.test"):
    xml = tmp_path / "zap.xml"
    xml.write_text(
        f'<OWASPZAPReport><site host="{host}" port="443"><alerts>{body}</alerts></site></OWASPZAPReport>',
        encoding="utf-8",
    )
    return ScanfuseEngine(str(tmp_path / "out")).process_file(str(xml), "zap")


def alert(name, instances, plugin="1"):
    inst = "".join(
        f"<instance><uri>{uri}</uri><method>{m}</method>{extra}</instance>" for m, uri, extra in instances
    )
    return (f"<alertitem><pluginid>{plugin}</pluginid><name>{name}</name><riskcode>3</riskcode>"
            f"<desc>d</desc><instances>{inst}</instances></alertitem>")


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


def test_same_title_with_different_cwe_ids_stays_separate():
    a = finding(title="Input validation", identifiers=["CWE-79"])
    b = finding(title="Input validation", identifiers=["CWE-89"])
    assert len(deduplicate_findings([a, b])) == 2


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


def test_different_identifier_prefixes_of_same_tool_stay_separate():
    a = finding(title="Plugin", tool="nessus", identifiers=["nessus-plugin:1"])
    b = finding(title="Plugin", tool="nessus", identifiers=["nessus-cve:2"])
    assert len(deduplicate_findings([a, b])) == 2


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
    # dummy_burp_view.xml reports the SQL injection at /view, the path ZAP reports it at.
    for name, fmt in (("dummy_zap.xml", "zap"), ("dummy_burp_view.xml", "burp")):
        findings += engine.process_file(os.path.join(FIXTURES, name), fmt)
    merged = [f for f in deduplicate_findings(findings) if f.sources]
    assert merged, "expected the SQL injection findings of ZAP and Burp to merge"
    for m in merged:
        original = [f for f in findings if f.title.strip().casefold() == m.title.strip().casefold()]
        assert {s.description for s in m.sources} == {f.description for f in original}
        assert {s.remediation for s in m.sources} == {f.remediation for f in original}


def test_fixtures_zap_and_burp_sql_injection_at_different_paths_stay_separate(tmp_path):
    # dummy_zap.xml has it at /view, dummy_burp.xml at /api/login. The old test expected one finding.
    engine = ScanfuseEngine(str(tmp_path))
    findings = []
    for name, fmt in (("dummy_zap.xml", "zap"), ("dummy_burp.xml", "burp")):
        findings += engine.process_file(os.path.join(FIXTURES, name), fmt)
    sql = [f for f in deduplicate_findings(findings) if f.title.casefold() == "sql injection"]
    assert len(sql) == 2
    assert {loc for f in sql for _m, loc in f.places()} == {"/view", "/api/login"}


def test_same_title_and_port_on_different_urls_are_two_findings():
    a = finding(tool="burp", port="443/tcp", location="/login", hosts=[Host(ip="10.0.0.1")])
    b = finding(tool="burp", port="443/tcp", location="/search", hosts=[Host(ip="10.0.0.1")])
    assert len(deduplicate_findings([a, b])) == 2


def test_different_parameter_on_the_same_path_is_a_separate_finding():
    a = finding(tool="burp", location="/search [q parameter]")
    b = finding(tool="burp", location="/search [id parameter]")
    assert len(deduplicate_findings([a, b])) == 2


def test_same_title_port_and_url_from_two_tools_is_one_finding():
    a = finding(tool="zap", port="443/tcp", location="/login")
    b = finding(title="sql injection", tool="burp", port="443/tcp", location=" /login ")
    (merged,) = deduplicate_findings([a, b])
    assert merged.source_tool == "zap, burp"
    assert merged.places() == {(None, "/login")}


def test_url_paths_are_case_sensitive():
    for first, second in (("/login", "/Login"), ("/admin", "/Admin"),
                          ("/search [q parameter]", "/search [Q parameter]")):
        a = finding(tool="zap", location=first)
        b = finding(tool="burp", location=second)
        assert len(deduplicate_findings([a, b])) == 2, (first, second)


def test_trailing_slash_is_a_different_location():
    a = finding(tool="zap", location="/admin")
    b = finding(tool="burp", location="/admin/")
    assert len(deduplicate_findings([a, b])) == 2


def test_same_location_with_different_methods_stays_separate():
    a = finding(tool="zap", location="/account", method="GET")
    b = finding(tool="zap", location="/account", method="POST")
    assert [f.places() for f in deduplicate_findings([a, b])] == [{("GET", "/account")}, {("POST", "/account")}]


def test_method_is_upper_cased_and_merges_across_tools():
    a = finding(tool="zap", location="/account", method="post")
    b = finding(tool="burp", location="/account", method=" POST")
    (merged,) = deduplicate_findings([a, b])
    assert a.observations[0].method == "POST"
    assert merged.places() == {("POST", "/account")}
    assert merged.source_tool == "zap, burp"


def test_finding_with_and_without_method_do_not_merge():
    a = finding(tool="zap", location="/account", method="GET")
    b = finding(tool="nuclei", location="/account")
    assert len(deduplicate_findings([a, b])) == 2


def test_zap_alert_with_several_locations_stays_one_finding_and_lists_them(tmp_path):
    (f,) = parse_zap(tmp_path, alert("XSS", [
        ("GET", "https://example.test/a", ""),
        ("POST", "https://example.test/b", "<param>q</param>"),
        ("GET", "https://example.test/a", ""),
    ]))
    assert len(f.observations) == 3
    assert f.affected() == ["example.test GET /a", "example.test POST /b [q parameter]"]
    assert f.place_labels() == ["GET /a", "POST /b [q parameter]"]


def test_zap_emits_one_observation_per_instance_with_host_and_source(tmp_path):
    (f,) = parse_zap(tmp_path, alert("XSS", [("post", "https://example.test/a", ""),
                                             ("GET", "https://example.test/a", "")]))
    assert [(o.host, o.method, o.location, o.source_tool) for o in f.observations] == [
        ("example.test", "POST", "/a", "zap"), ("example.test", "GET", "/a", "zap")]


def test_zap_and_burp_with_same_method_and_location_merge(tmp_path):
    (z,) = parse_zap(tmp_path, alert("SQL Injection", [("POST", "https://example.test/account", "")]))
    burp = tmp_path / "burp.xml"
    burp.write_text(
        "<issues><issue><name>SQL Injection</name><host ip=\"192.0.2.1\">https://example.test</host>"
        "<path>/account</path><severity>High</severity><requestresponse>"
        "<request method=\"POST\">POST /account HTTP/1.1</request></requestresponse></issue></issues>",
        encoding="utf-8",
    )
    (b,) = ScanfuseEngine(str(tmp_path / "out")).process_file(str(burp), "burp")
    assert z.places() == b.places() == {("POST", "/account")}
    (merged,) = deduplicate_findings([z, b])
    assert merged.source_tool == "zap, burp"
    assert {(o.host, o.source_tool) for o in merged.observations} == {
        ("example.test", "zap"), ("192.0.2.1", "burp")}


def test_burp_method_comes_from_attribute_or_request_line(tmp_path):
    def parse(request_xml):
        xml = tmp_path / "burp.xml"
        xml.write_text(
            "<issues><issue><name>X</name><severity>Low</severity><path>/p</path>"
            f"{request_xml}</issue></issues>",
            encoding="utf-8",
        )
        (f,) = ScanfuseEngine(str(tmp_path / "out")).process_file(str(xml), "burp")
        (o,) = f.observations
        return o.method

    assert parse('<requestresponse><request method="put">x</request></requestresponse>') == "PUT"
    assert parse("<requestresponse><request>delete /p HTTP/1.1</request></requestresponse>") == "DELETE"
    two = "<requestresponse><request>GET /p HTTP/1.1</request></requestresponse>" \
          "<requestresponse><request>POST /p HTTP/1.1</request></requestresponse>"
    assert parse(two) is None
    assert parse("") is None


def test_nuclei_observation_has_the_path_of_a_url_match_only(tmp_path):
    import json
    rows = [
        {"template-id": "t", "info": {"name": "T", "severity": "low"}, "host": "https://a.test",
         "matched-at": "https://a.test/x/y?q=1"},
        {"template-id": "t", "info": {"name": "T", "severity": "low"}, "host": "a.test:22",
         "matched-at": "a.test:22"},
    ]
    path = tmp_path / "n.json"
    path.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")
    web, network = ScanfuseEngine(str(tmp_path / "out")).process_file(str(path), "nuclei")
    assert [(o.location, o.source_tool) for o in web.observations] == [("/x/y", "nuclei")]
    assert network.observations[0].location is None


def test_same_url_on_several_hosts_is_one_finding_with_all_hosts():
    a = finding(tool="zap", location="/login", hosts=[Host(ip="10.0.0.1")])
    b = finding(tool="zap", location="/login", hosts=[Host(ip="10.0.0.2")])
    (merged,) = deduplicate_findings([a, b])
    assert {h.ip for h in merged.hosts} == {"10.0.0.1", "10.0.0.2"}
    assert {(o.host, o.location) for o in merged.observations} == {
        ("10.0.0.1", "/login"), ("10.0.0.2", "/login")}


def test_findings_without_location_still_merge_as_before():
    a = finding(tool="nuclei", hosts=[Host(ip="10.0.0.1")])
    b = finding(tool="nuclei", hosts=[Host(ip="10.0.0.2")])
    (merged,) = deduplicate_findings([a, b])
    assert [(o.host, o.location) for o in merged.observations] == [("10.0.0.1", None), ("10.0.0.2", None)]
    assert merged.affected() == []


def test_disjoint_multi_instance_alerts_on_two_hosts_stay_two_findings(tmp_path):
    a = parse_zap(tmp_path, alert("XSS", [("GET", "https://a.test/a1", ""), ("GET", "https://a.test/a2", "")]),
                  host="host-a")
    b = parse_zap(tmp_path, alert("XSS", [("GET", "https://b.test/b1", ""), ("GET", "https://b.test/b2", "")]),
                  host="host-b")
    merged = deduplicate_findings(a + b)
    assert len(merged) == 2
    assert [{loc for _m, loc in f.places()} for f in merged] == [{"/a1", "/a2"}, {"/b1", "/b2"}]


def test_multi_instance_alerts_with_the_same_locations_merge_across_tools_and_hosts(tmp_path):
    a = parse_zap(tmp_path, alert("XSS", [("GET", "https://a.test/p", ""), ("POST", "https://a.test/q", "")]),
                  host="host-a")
    b = parse_zap(tmp_path, alert("XSS", [("POST", "https://b.test/q", ""), ("GET", "https://b.test/p", "")]),
                  host="host-b")
    burp = finding(title="xss", tool="burp", places=[("GET", "/p"), ("POST", "/q")],
                   port="443/tcp", hosts=[Host(ip="192.0.2.9")])
    (merged,) = deduplicate_findings(a + b + [burp])
    assert merged.source_tool == "zap, burp"
    assert {(o.host, o.method, o.location, o.source_tool) for o in merged.observations} == {
        ("host-a", "GET", "/p", "zap"), ("host-a", "POST", "/q", "zap"),
        ("host-b", "POST", "/q", "zap"), ("host-b", "GET", "/p", "zap"),
        ("192.0.2.9", "GET", "/p", "burp"), ("192.0.2.9", "POST", "/q", "burp")}


def test_host_without_observation_gets_a_host_only_observation():
    a = finding(tool="nmap", hosts=[Host(ip="10.0.0.1"), Host(ip="unknown", hostname="h.test")])
    b = finding(tool="nmap", hosts=[Host(ip="10.0.0.3")])
    (merged,) = deduplicate_findings([a, b])
    assert [o.host for o in merged.observations] == ["10.0.0.1", "h.test", "10.0.0.3"]


def test_zap_alert_with_several_instances_stays_one_finding(tmp_path):
    findings = parse_zap(tmp_path, alert("XSS", [("GET", "http://10.0.0.5/a", ""),
                                                  ("GET", "http://10.0.0.5/b", "")]), host="10.0.0.5")
    assert len(deduplicate_findings(findings)) == 1
    assert len(findings[0].evidence) == 2
    assert len(findings[0].observations) == 2


def test_zap_and_burp_parsers_fill_observations():
    engine = ScanfuseEngine("unused")
    zap = engine.process_file(os.path.join(FIXTURES, "dummy_zap.xml"), "zap")
    burp = engine.process_file(os.path.join(FIXTURES, "dummy_burp.xml"), "burp")
    sql = [f for f in zap if f.title == "SQL Injection"]
    assert {loc for f in sql for _m, loc in f.places()} == {"/view"}
    assert burp[0].places() == {(burp[0].observations[0].method, "/api/login")}
    assert burp[0].observations[0].source_tool == "burp"
