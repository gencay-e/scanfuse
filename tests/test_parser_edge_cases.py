import json

import pytest

from scanfuse.parsers.grype import GrypeParser
from scanfuse.parsers.nikto import NiktoParser
from scanfuse.parsers.nuclei import NucleiParser
from scanfuse.parsers.testssl import TestsslParser


def _write_json(tmp_path, name, payload):
    path = tmp_path / name
    path.write_text(json.dumps(payload), encoding="utf-8-sig")
    return str(path)


def test_nikto_csv_keeps_blank_id_and_normalizes_mixed_case_headers(tmp_path):
    nikto = tmp_path / "nikto.csv"
    nikto.write_text('Nikto - v2.5.0\n"web.test","192.0.2.4","80","","GET",'
                     '"https://web.test/path","Visible finding"\n', encoding="utf-8-sig")
    (finding,) = NiktoParser().parse(str(nikto))
    assert finding.title == "Visible finding"
    assert finding.references == ["https://web.test/path"]

    headers = tmp_path / "headers.csv"
    headers.write_text("HOST,PORT,ID,SEVERITY,MSG\nweb.test,443,abc,High,Finding\n", encoding="utf-8")
    (finding,) = NiktoParser().parse(str(headers))
    assert finding.title == "Finding"
    assert finding.severity == "High"


def test_nikto_detection_and_parser_share_utf16_xml_encoding(tmp_path):
    from scanfuse.engine import ScanfuseEngine

    source = tmp_path / "nikto-utf16.xml"
    source.write_text('<niktoscan><scandetails targetip="192.0.2.7"><item id="3">'
                      '<description>UTF16 finding</description></item></scandetails></niktoscan>',
                      encoding="utf-16")
    assert ScanfuseEngine._detect_format(str(source)) == "nikto"
    assert NiktoParser().parse(str(source))[0].title == "UTF16 finding"


def test_nikto_rejects_unknown_xml_root_with_item(tmp_path):
    source = tmp_path / "other.xml"
    source.write_text("<other><item id='1'>not nikto</item></other>", encoding="utf-8")
    with pytest.raises(ValueError, match="Not a valid Nikto XML"):
        NiktoParser().parse(str(source))


def test_nikto_json_list_and_scandetails(tmp_path):
    json_list = _write_json(tmp_path, "list.json", [{
        "ip": "192.0.2.4", "port": 80, "vulnerabilities": [{"id": "1", "msg": "List finding"}],
    }])
    assert NiktoParser().parse(json_list)[0].title == "List finding"
    scan_details = _write_json(tmp_path, "details.json", {
        "scanDetails": [{"id": "2", "host": "192.0.2.5", "msg": "Details finding"}],
    })
    assert NiktoParser().parse(scan_details)[0].title == "Details finding"


def test_nikto_xml_error_rootcheck_host_and_references(tmp_path):
    malformed = tmp_path / "bad.xml"
    malformed.write_text("<scandetails><item>", encoding="utf-8")
    with pytest.raises(ValueError, match="Invalid Nikto XML"):
        NiktoParser().parse(str(malformed))

    xml = tmp_path / "root.xml"
    xml.write_text('<scandetails targetip="192.0.2.4" targethostname="web.test" targetport="443">'
                   '<item id="7" method="GET"><description>Finding</description><uri>/x</uri>'
                   '<references>https://example.test/ref</references></item></scandetails>', encoding="utf-8")
    (finding,) = NiktoParser().parse(str(xml))
    assert finding.observations[0].host == "192.0.2.4"
    assert finding.references == ["https://example.test/ref"]


def test_nikto_references_json_and_invalid_url_are_safe(tmp_path):
    path = _write_json(tmp_path, "nikto.json", {"vulnerabilities": [{
        "id": "1", "host": "192.0.2.4", "url": "http://[::1", "references": "https://example.test/ref",
        "msg": "Finding",
    }]})
    (finding,) = NiktoParser().parse(path)
    assert "https://example.test/ref" in finding.references


def test_nuclei_empty_array_and_url_observation_port_query(tmp_path):
    empty = tmp_path / "empty.json"
    empty.write_text("[]", encoding="utf-8")
    assert NucleiParser().parse(str(empty)) == []
    path = _write_json(tmp_path, "nuclei.json", {
        "template-id": "t", "info": {"name": "Finding"},
        "host": "https://example.test:8443/path?q=one", "matched-at": "https://example.test:8443/path?q=one",
    })
    (finding,) = NucleiParser().parse(path)
    assert finding.hosts[0].ip == "unknown"
    assert finding.hosts[0].hostname == "example.test"
    assert finding.hosts[0].port == 8443
    assert finding.port == "8443/tcp"
    assert finding.observations[0].host == "example.test"
    assert finding.observations[0].location == "/path?q=one"

    matched_only = _write_json(tmp_path, "matched-only.json", {
        "template-id": "t", "info": {}, "matched-at": "https://target.test:8443/only",
    })
    matched_finding = NucleiParser().parse(matched_only)[0]
    assert matched_finding.observations[0].host == "target.test"
    assert matched_finding.hosts[0].port == 8443

    invalid_port = _write_json(tmp_path, "bad-port.json", {
        "template-id": "t", "info": {}, "host": "https://example.test:bad/path",
    })
    bad_port_finding = NucleiParser().parse(invalid_port)[0]
    assert bad_port_finding.hosts[0].hostname == "example.test"
    assert bad_port_finding.port is None


def test_grype_null_context_related_ids_and_bad_fix_versions(tmp_path):
    path = _write_json(tmp_path, "grype.json", {
        "context": None, "matches": [{
            "vulnerability": {"id": "GHSA-abcd-efgh-ijkl", "severity": "High", "fix": {"versions": "unknown"}},
            "relatedVulnerabilities": [{"id": "CVE-2024-1111"}], "artifact": {"name": "demo"},
        }],
    })
    (finding,) = GrypeParser().parse(path)
    assert "CVE-2024-1111" in finding.identifiers
    assert finding.remediation is None


def test_testssl_single_object_multivalue_ids_and_tcp_port(tmp_path):
    path = _write_json(tmp_path, "testssl.json", {
        "id": "HEARTBLEED", "severity": "HIGH", "finding": "Vulnerable",
        "ip": "192.0.2.4", "port": "443/tcp",
        "cve": "CVE-2014-0160, CVE-2014-0161", "cwe": "CWE-119 CWE-120",
    })
    (finding,) = TestsslParser().parse(path)
    assert finding.identifiers == ["HEARTBLEED", "CVE-2014-0160", "CVE-2014-0161", "CWE-119", "CWE-120"]
    assert finding.hosts[0].port == 443
    assert finding.port == "443/tcp"


@pytest.mark.parametrize("wrapper", [
    {"scanDetails": {"ip": "192.0.2.8", "port": 8443, "vulnerabilities": [{"msg": "Nested"}]}},
    {"scanDetails": [{"ip": "192.0.2.8", "port": 8443, "items": [{"msg": "Nested"}]}]},
    {"scanDetails": {"items": [{"ip": "192.0.2.8", "port": 8443, "msg": "Nested"}]}},
])
def test_nikto_nested_scan_details_preserves_target(tmp_path, wrapper):
    path = _write_json(tmp_path, "nested.json", wrapper)
    (finding,) = NiktoParser().parse(path)
    assert finding.title == "Nested"
    assert finding.hosts[0].ip == "192.0.2.8"
    assert finding.port == "8443/tcp"


def test_nikto_csv_reference_id_is_also_a_reference(tmp_path):
    path = tmp_path / "reference.csv"
    path.write_text('Nikto - v2.6.1\n"web.test","192.0.2.8","80",'
                    '"https://example.test/advisory","GET","/path","Finding"\n', encoding="utf-8")
    (finding,) = NiktoParser().parse(str(path))
    assert finding.identifiers == ["https://example.test/advisory"]
    assert finding.references == ["https://example.test/advisory"]


def test_nikto_truncated_utf16_is_a_report_error(tmp_path):
    path = tmp_path / "truncated.xml"
    path.write_bytes(b"\xff\xfe<")
    with pytest.raises(ValueError) as error:
        NiktoParser().parse(str(path))
    assert not isinstance(error.value, UnicodeDecodeError)


@pytest.mark.parametrize("depth", [200, 2000])
def test_nikto_deep_wrappers_are_controlled_errors(tmp_path, depth):
    path = tmp_path / "deep.json"
    path.write_text("[" * depth + '{"msg":"Nested"}' + "]" * depth, encoding="utf-8")
    with pytest.raises(ValueError):
        NiktoParser().parse(str(path))


def test_trivy_malformed_containers_and_dot_artifact(tmp_path):
    from typer.testing import CliRunner

    from scanfuse.cli import app
    from scanfuse.engine import ScanfuseEngine
    from scanfuse.models import Finding
    from scanfuse.parsers.base import PartialImportError
    from scanfuse.parsers.trivy import TrivyParser

    base_dir = tmp_path / "baseline"
    ScanfuseEngine(str(base_dir)).export_json([
        Finding(title="Existing", severity="High", description="D", source_tool="trivy"),
    ])

    bad_results = _write_json(tmp_path, "bad-trivy.json", {"SchemaVersion": 2, "Results": {"unexpected": "object"}})
    out = tmp_path / "out-bad-trivy"
    result = CliRunner().invoke(
        app, [bad_results, "-f", "trivy", "--baseline", str(base_dir / "report.json"), "--format-out", "json", "-o", str(out)],
    )
    assert result.exit_code == 1, result.output
    report = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert report["complete"] is False and report["resolved"] == []

    partial_path = _write_json(tmp_path, "partial-trivy.json", {
        "SchemaVersion": 2,
        "Results": [
            {"Target": "a", "Vulnerabilities": [{"VulnerabilityID": "CVE-2024-1"}]},
            {"Target": "b", "Vulnerabilities": "wrong-type"},
        ],
    })
    with pytest.raises(PartialImportError) as err:
        TrivyParser().parse(partial_path)
    assert len(err.value.findings) == 1

    dot_path = _write_json(tmp_path, "dot-trivy.json", {
        "SchemaVersion": 2,
        "ArtifactName": ".",
        "ArtifactType": "filesystem",
        "Results": [{"Target": "package.json", "Vulnerabilities": [{"VulnerabilityID": "CVE-2024-2"}]}],
    })
    (finding,) = TrivyParser().parse(dot_path)
    assert (finding.hosts[0].ip, finding.hosts[0].hostname) == ("local", "filesystem")


def test_semgrep_top_level_errors_mark_run_incomplete(tmp_path):
    from typer.testing import CliRunner

    from scanfuse.cli import app
    from scanfuse.engine import ScanfuseEngine
    from scanfuse.models import Finding

    base_dir = tmp_path / "baseline"
    ScanfuseEngine(str(base_dir)).export_json([
        Finding(title="Existing", severity="High", description="D", source_tool="semgrep"),
    ])

    empty_err = _write_json(tmp_path, "semgrep-err.json", {
        "results": [],
        "errors": [{"type": "ParseError", "message": "Failed to parse target"}],
    })
    out = tmp_path / "out-semgrep-err"
    result = CliRunner().invoke(
        app, [empty_err, "-f", "semgrep", "--baseline", str(base_dir / "report.json"), "--format-out", "json", "-o", str(out)],
    )
    assert result.exit_code == 1, result.output
    report = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert report["complete"] is False and report["resolved"] == []

    partial_err = _write_json(tmp_path, "semgrep-partial.json", {
        "results": [{"check_id": "rule-1", "path": "app.py", "start": {"line": 3}, "extra": {"message": "Hit"}}],
        "errors": [{"type": "ParseError", "message": "Failed on other file"}],
    })
    out2 = tmp_path / "out-semgrep-partial"
    result2 = CliRunner().invoke(app, [partial_err, "-f", "semgrep", "--format-out", "json", "-o", str(out2)])
    assert result2.exit_code == 1, result2.output
    report2 = json.loads((out2 / "report.json").read_text(encoding="utf-8"))
    assert report2["complete"] is False and len(report2["findings"]) == 1


def test_aborted_scans_and_malformed_list_entries_report_errors(tmp_path):
    from scanfuse.parsers.base import PartialImportError
    from scanfuse.parsers.nmap import NmapParser
    from scanfuse.parsers.sarif import SarifParser
    from scanfuse.parsers.semgrep import SemgrepParser
    from scanfuse.parsers.trivy import TrivyParser

    nmap_abort = tmp_path / "nmap-abort.xml"
    nmap_abort.write_text('<nmaprun><runstats><finished exit="error" errormsg="Failed scan"/></runstats></nmaprun>', encoding="utf-8")
    with pytest.raises(ValueError, match="Failed scan"):
        NmapParser().parse(str(nmap_abort))

    sarif_abort = _write_json(tmp_path, "sarif-abort.sarif", {
        "version": "2.1.0",
        "runs": [{"invocations": [{"executionSuccessful": False}], "results": []}],
    })
    with pytest.raises(PartialImportError):
        SarifParser().parse(sarif_abort)

    for parser_cls, name, payload in (
        (SarifParser, "sarif-bad-results.sarif", {"version": "2.1.0", "runs": [{"results": {}}]}),
        (TestsslParser, "testssl-bad.json", {"scanResult": {}}),
        (NiktoParser, "nikto-bad.json", {"vulnerabilities": {}}),
        (SemgrepParser, "semgrep-null.json", {"results": [None]}),
        (GrypeParser, "grype-null.json", {"matches": [None]}),
        (TrivyParser, "trivy-null.json", {"SchemaVersion": 2, "Results": [{"Target": "app", "Vulnerabilities": [None]}]}),
    ):
        bad_path = _write_json(tmp_path, name, payload)
        with pytest.raises((ValueError, PartialImportError)):
            parser_cls().parse(bad_path)


def test_testssl_flat_target_host_and_partial_fatal(tmp_path):
    from scanfuse.parsers.base import PartialImportError

    flat = _write_json(tmp_path, "flat-target.json", [
        {"id": "x", "severity": "HIGH", "finding": "vulnerable", "targetHost": "example.test"},
    ])
    (finding,) = TestsslParser().parse(flat)
    assert finding.title == "x" and finding.hosts[0].ip == "example.test"

    mixed = _write_json(tmp_path, "mixed-fatal.json", [
        {"id": "x", "severity": "HIGH", "finding": "vulnerable", "ip": "192.0.2.1"},
        {"id": "fatal", "severity": "FATAL", "finding": "Can't connect"},
    ])
    with pytest.raises(PartialImportError) as err:
        TestsslParser().parse(mixed)
    assert len(err.value.findings) == 1


def test_sarif_artifacts_index_kind_filter_and_unhashable_severity(tmp_path):
    from scanfuse.parsers.sarif import SarifParser
    from scanfuse.utils import deduplicate_findings

    path = _write_json(tmp_path, "artifacts.sarif", {
        "version": "2.1.0",
        "runs": [{
            "artifacts": [{"location": {"uri": "a.py"}}, {"location": {"uri": "b.py"}}],
            "results": [
                {"ruleId": "r1", "kind": "fail", "properties": {"scanfuse-severity": []},
                 "message": {"text": "Hit"},
                 "locations": [{"physicalLocation": {"artifactLocation": {"index": 0}, "region": {"startLine": 1}}}]},
                {"ruleId": "r1", "kind": "fail",
                 "message": {"text": "Hit"},
                 "locations": [{"physicalLocation": {"artifactLocation": {"index": 1}, "region": {"startLine": 1}}}]},
                {"ruleId": "r1", "kind": "pass", "message": {"text": "OK"}},
            ],
        }],
    })
    findings = SarifParser().parse(path)
    assert len(findings) == 2
    assert {f.observations[0].location for f in findings} == {"a.py:1", "b.py:1"}
    assert len(deduplicate_findings(findings)) == 2


def test_nuclei_network_ports_ipv6_trivy_pass_and_large_cvss(tmp_path):
    from scanfuse.parsers.trivy import TrivyParser
    from scanfuse.utils import deduplicate_findings

    nuclei_net = _write_json(tmp_path, "nuclei-net.json", [
        {"template-id": "banner", "info": {"name": "Banner", "classification": {"cvss-score": 10**400}}, "host": "example.test:22"},
        {"template-id": "banner", "info": {"name": "Banner"}, "host": "example.test:443"},
        {"template-id": "banner", "info": {"name": "Banner"}, "host": "[2001:db8::1]:2222"},
    ])
    n_findings = NucleiParser().parse(nuclei_net)
    assert [f.port for f in n_findings] == ["22/tcp", "443/tcp", "2222/tcp"]
    assert n_findings[0].cvss_score is None
    assert n_findings[0].hosts[0].hostname == "example.test"
    assert n_findings[2].hosts[0].ip == "2001:db8::1"
    assert len(deduplicate_findings(n_findings[:2])) == 2

    grype_huge = _write_json(tmp_path, "grype-huge.json", {"matches": [{
        "vulnerability": {"id": "CVE-2024-1", "severity": "HIGH", "cvss": [{"metrics": {"baseScore": 10**400}}]},
        "artifact": {"name": "pkg"},
    }]})
    assert GrypeParser().parse(grype_huge)[0].cvss_score is None

    trivy_pass = _write_json(tmp_path, "trivy-pass.json", {
        "SchemaVersion": 2,
        "Results": [{"Target": "main.tf", "Misconfigurations": [
            {"ID": "OK1", "Title": "Passed", "Severity": "HIGH", "Status": "PASS"},
            {"ID": "FAIL1", "Title": "Broken", "Severity": "HIGH", "Status": "FAIL"},
        ]}],
    })
    t_findings = TrivyParser().parse(trivy_pass)
    assert [f.title for f in t_findings] == ["Broken"]


def test_burp_location_preserves_entities_rejects_bad_base64_and_nikto_csv_multiline(tmp_path):
    from scanfuse.parsers.burp import BurpParser
    from scanfuse.utils import deduplicate_findings

    burp_xml = tmp_path / "burp-edge.xml"
    burp_xml.write_text(
        '<issues>'
        '<issue><name>XSS</name><host ip="192.0.2.1">http://example.test</host>'
        '<location>/search?a=1&amp;amp;b=2</location><severity>High</severity></issue>'
        '<issue><name>XSS</name><host ip="192.0.2.1">http://example.test</host>'
        '<location>/search?a=1&amp;b=2</location><severity>High</severity></issue>'
        '<issue><name>BadB64</name><host ip="192.0.2.1">http://example.test</host>'
        '<location>/ok</location><severity>Low</severity>'
        '<requestresponse><request base64="true">!!!!</request></requestresponse></issue>'
        '</issues>',
        encoding="utf-8",
    )
    findings = BurpParser().parse(str(burp_xml))
    assert len(findings) == 3
    xss = [f for f in findings if f.title == "XSS"]
    assert {f.observations[0].location for f in xss} == {"/search?a=1&amp;b=2", "/search?a=1&b=2"}
    assert len(deduplicate_findings(xss)) == 2
    bad_b64 = next(f for f in findings if f.title == "BadB64")
    http_ev = next(e.data for e in bad_b64.evidence if e.type == "http-request")
    assert "Request:\n!!!!" in http_ev

    nikto_csv = tmp_path / "multiline.csv"
    nikto_csv.write_text(
        'Nikto - v2.6.1\n'
        '"web.test","192.0.2.1","80","1","GET","/","first\nsecond"\n',
        encoding="utf-8",
    )
    (n_finding,) = NiktoParser().parse(str(nikto_csv))
    assert n_finding.description == "first\nsecond"


def test_nikto_rejects_null_containers_and_malformed_csv_rows(tmp_path):
    from typer.testing import CliRunner

    from scanfuse.cli import app
    from scanfuse.engine import ScanfuseEngine
    from scanfuse.parsers.base import PartialImportError

    for key in ("vulnerabilities", "items", "scanDetails"):
        path = _write_json(tmp_path, f"nikto_{key}_null.json", {key: None})
        with pytest.raises(ValueError):
            NiktoParser().parse(path)
        with pytest.raises(ValueError):
            ScanfuseEngine(str(tmp_path)).process_file(path, "nikto")

    mixed_json = _write_json(
        tmp_path,
        "nikto_mixed_null.json",
        [
            {"host": "web.test", "vulnerabilities": [{"id": "1", "msg": "Valid entry"}]},
            {"host": "web.test", "vulnerabilities": None},
        ],
    )
    with pytest.raises(PartialImportError) as exc_info:
        NiktoParser().parse(mixed_json)
    assert [f.title for f in exc_info.value.findings] == ["Valid entry"]

    engine = ScanfuseEngine(str(tmp_path))
    with pytest.raises(PartialImportError) as engine_exc:
        engine.process_file(mixed_json, "auto")
    assert [f.title for f in engine_exc.value.findings] == ["Valid entry"]

    base_json = _write_json(
        tmp_path,
        "nikto_base.json",
        {"host": "web.test", "vulnerabilities": [{"id": "99", "msg": "Baseline entry"}]},
    )
    base_dir = tmp_path / "base_out"
    base_res = CliRunner().invoke(app, [base_json, "--output", str(base_dir), "--format-out", "json"])
    assert base_res.exit_code == 0, base_res.output
    baseline = base_dir / "report.json"

    broken_csv = tmp_path / "nikto_broken.csv"
    broken_csv.write_text(
        '"Nikto - v2.6.1/"\n'
        '"192.0.2.1","192.0.2.1","80","","","",""\n'
        '"web.test","192.0.2.1","80","1","GET","/ok","Valid CSV finding"\n'
        '"web.test","192.0.2.1","80","2","GET","/truncated"\n',
        encoding="utf-8",
    )
    with pytest.raises(PartialImportError) as csv_exc:
        NiktoParser().parse(str(broken_csv))
    assert [f.title for f in csv_exc.value.findings] == ["Valid CSV finding"]

    out_dir = tmp_path / "out"
    res = CliRunner().invoke(
        app,
        [str(broken_csv), "--baseline", str(baseline), "--output", str(out_dir), "--format-out", "json"],
    )
    assert res.exit_code == 1
    report = json.loads((out_dir / "report.json").read_text(encoding="utf-8"))
    assert report["complete"] is False
    assert report["errors"]
    assert report["resolved"] == []
    assert [f["title"] for f in report["findings"]] == ["Valid CSV finding"]


@pytest.mark.parametrize("bad", [None, [], 42, "invalid"])
def test_grype_invalid_vulnerability_preserves_valid_match_and_marks_cli_incomplete(tmp_path, bad):
    from typer.testing import CliRunner

    from scanfuse.cli import app
    from scanfuse.parsers.base import PartialImportError

    good = {"vulnerability": {"id": "CVE-2026-12345", "severity": "High"},
            "artifact": {"name": "package"}}
    path = _write_json(tmp_path, "grype.json", {"matches": [good, {"vulnerability": bad}]})
    with pytest.raises(PartialImportError, match="vulnerability.*object") as error:
        GrypeParser().parse(path)
    assert [f.title for f in error.value.findings] == ["CVE-2026-12345 in package"]
    output = tmp_path / "report"
    result = CliRunner().invoke(app, [path, "-f", "grype", "--format-out", "json", "-o", str(output)])
    assert result.exit_code == 1
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    assert report["complete"] is False
    assert len(report["findings"]) == len(report["errors"]) == 1


@pytest.mark.parametrize("bad", [{}, {"severity": "HIGH"},
                              {"id": "overflow", "severity": "HIGH", "port": float("inf")}])
def test_testssl_malformed_flat_record_preserves_valid_check_and_marks_cli_incomplete(tmp_path, bad):
    from typer.testing import CliRunner

    from scanfuse.cli import app
    from scanfuse.parsers.base import PartialImportError

    good = {"id": "SSLv3", "severity": "HIGH", "finding": "enabled", "port": "443"}
    path = _write_json(tmp_path, "tls.json", [good, bad])
    with pytest.raises(PartialImportError) as error:
        TestsslParser().parse(path)
    assert [f.title for f in error.value.findings] == ["SSLv3"]
    output = tmp_path / "report"
    result = CliRunner().invoke(app, [path, "-f", "testssl", "--format-out", "json", "-o", str(output)])
    assert result.exit_code == 1
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    assert report["complete"] is False
    assert len(report["findings"]) == len(report["errors"]) == 1
