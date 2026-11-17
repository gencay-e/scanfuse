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
